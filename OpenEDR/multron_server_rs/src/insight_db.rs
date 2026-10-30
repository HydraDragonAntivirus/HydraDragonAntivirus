//! SQLite store of `threat_insights`: one row per hash, replaced in place.
//!
//! Replaces the append-only `threat_insights.jsonl`, which wrote a hash's whole entry
//! again on every update and kept every older copy (16 GB). `seq` grows with each write
//! and is the change feed for the archive mirror and the seamless update: "rows with
//! `seq` above what I last saw". The old `.jsonl` is never touched or deleted.

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{params, Connection, OpenFlags};

use crate::cache::Sha;

pub struct InsightDb {
    conn: Mutex<Connection>,
}

type Res<T> = rusqlite::Result<T>;

fn tune(conn: &Connection) -> Res<()> {
    conn.busy_timeout(Duration::from_secs(30))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    Ok(())
}

impl InsightDb {
    /// Opens (creating when missing) the database for reading and writing.
    pub fn open(path: &Path) -> Res<Self> {
        let conn = Connection::open(path)?;
        tune(&conn)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS insights (
                 sha  BLOB PRIMARY KEY,
                 seq  INTEGER NOT NULL,
                 data BLOB NOT NULL
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS insights_seq ON insights(seq);
             CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);",
        )?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Opens an existing database for reading only (archive, standby).
    pub fn open_readonly(path: &Path) -> Res<Self> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        conn.busy_timeout(Duration::from_secs(30))?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn count(&self) -> Res<u64> {
        let c = self.conn.lock().unwrap();
        c.query_row("SELECT COUNT(*) FROM insights", [], |r| r.get::<_, i64>(0)).map(|n| n as u64)
    }

    /// Highest `seq` written so far (0 when empty).
    pub fn max_seq(&self) -> Res<i64> {
        let c = self.conn.lock().unwrap();
        c.query_row("SELECT COALESCE(MAX(seq), 0) FROM insights", [], |r| r.get(0))
    }

    pub fn meta(&self, key: &str) -> Option<String> {
        let c = self.conn.lock().unwrap();
        c.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).ok()
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Res<()> {
        let c = self.conn.lock().unwrap();
        c.execute("INSERT INTO meta(key, value) VALUES(?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value", [key, value])?;
        Ok(())
    }

    /// Inserts or replaces the entries in one transaction; each gets the next `seq`
    /// (read inside the transaction, so another process writing at the same time cannot
    /// hand out the same number).
    pub fn upsert_batch<'a>(&self, items: impl IntoIterator<Item = (&'a Sha, &'a [u8])>) -> Res<()> {
        let mut c = self.conn.lock().unwrap();
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        {
            let mut seq: i64 = tx.query_row("SELECT COALESCE(MAX(seq), 0) FROM insights", [], |r| r.get(0))?;
            let mut st = tx.prepare_cached(
                "INSERT INTO insights(sha, seq, data) VALUES(?1, ?2, ?3)
                 ON CONFLICT(sha) DO UPDATE SET seq = excluded.seq, data = excluded.data",
            )?;
            for (sha, data) in items {
                seq += 1;
                st.execute(params![&sha[..], seq, data])?;
            }
        }
        tx.commit()
    }

    /// Every entry, in hash order, to fill the in-memory table at start.
    pub fn for_each(&self, mut f: impl FnMut(Sha, &[u8])) -> Res<()> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare("SELECT sha, data FROM insights")?;
        let mut rows = st.query([])?;
        while let Some(row) = rows.next()? {
            let sha: Vec<u8> = row.get_ref(0)?.as_blob()?.to_vec();
            let Ok(sha) = Sha::try_from(sha.as_slice()) else { continue };
            f(sha, row.get_ref(1)?.as_blob()?);
        }
        Ok(())
    }

    /// Entries written after `seq`, oldest change first, at most `limit`:
    /// `(seq, json)`. The change feed for the archive mirror and the standby.
    pub fn changes_since(&self, seq: i64, limit: usize) -> Res<Vec<(i64, Vec<u8>)>> {
        let c = self.conn.lock().unwrap();
        let mut st = c.prepare_cached("SELECT seq, data FROM insights WHERE seq > ?1 ORDER BY seq LIMIT ?2")?;
        let rows = st.query_map(params![seq, limit as i64], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("insight_db_{}_{name}.db", std::process::id()));
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", p.display()));
        }
        p
    }

    #[test]
    fn upsert_replaces_in_place_and_orders_changes() {
        let db = InsightDb::open(&tmp("upsert")).unwrap();
        let (a, b) = ([1u8; 32], [2u8; 32]);
        db.upsert_batch([(&a, &b"a1"[..]), (&b, &b"b1"[..])]).unwrap();
        db.upsert_batch([(&a, &b"a2"[..])]).unwrap();
        assert_eq!(db.count().unwrap(), 2, "one row per hash");
        assert_eq!(db.max_seq().unwrap(), 3);
        let all = db.changes_since(0, 10).unwrap();
        assert_eq!(all, vec![(2, b"b1".to_vec()), (3, b"a2".to_vec())], "the replaced copy is gone, newest change last");
        assert_eq!(db.changes_since(2, 10).unwrap(), vec![(3, b"a2".to_vec())]);
    }

    #[test]
    fn for_each_returns_the_live_rows() {
        let db = InsightDb::open(&tmp("each")).unwrap();
        let a = [7u8; 32];
        db.upsert_batch([(&a, &b"x"[..])]).unwrap();
        db.upsert_batch([(&a, &b"y"[..])]).unwrap();
        let mut got = Vec::new();
        db.for_each(|s, d| got.push((s, d.to_vec()))).unwrap();
        assert_eq!(got, vec![(a, b"y".to_vec())]);
    }

    #[test]
    fn readonly_sees_what_the_writer_wrote() {
        let p = tmp("ro");
        let w = InsightDb::open(&p).unwrap();
        w.upsert_batch([(&[9u8; 32], &b"z"[..])]).unwrap();
        let r = InsightDb::open_readonly(&p).unwrap();
        assert_eq!(r.max_seq().unwrap(), 1);
        w.upsert_batch([(&[8u8; 32], &b"w"[..])]).unwrap();
        assert_eq!(r.changes_since(1, 10).unwrap().len(), 1);
    }

    #[test]
    fn meta_round_trip() {
        let db = InsightDb::open(&tmp("meta")).unwrap();
        assert_eq!(db.meta("k"), None);
        db.set_meta("k", "1").unwrap();
        db.set_meta("k", "2").unwrap();
        assert_eq!(db.meta("k").as_deref(), Some("2"));
    }
}
