//! SQLite store of `threat_insights`: one row per hash, replaced in place.
//!
//! Replaces the append-only `threat_insights.jsonl`, which wrote a hash's whole entry
//! again on every update and kept every older copy (16 GB). `seq` grows with each write
//! and is the change feed for the archive mirror and the seamless update: "rows with
//! `seq` above what I last saw". The old `.jsonl` is never touched or deleted.
//!
//! The JSON in `data` is the record. The columns next to it (verdict, threat, times,
//! seen count) and the `sightings` table are copies of fields in it, kept so the
//! dashboard and the statistics can ask SQLite instead of holding every record in
//! memory. `cols_seq` is the `seq` they were computed for: a row whose `cols_seq`
//! differs from its `seq` was written by a version that did not know the columns (the
//! old server during a seamless update) and is filled again (`stale_rows`).

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{params, Connection, OpenFlags};

use crate::cache::Sha;

/// SQLite page cache of each connection, in KiB (negative `cache_size`).
const WRITE_CACHE_KIB: i64 = 64 * 1024;
const LOOKUP_CACHE_KIB: i64 = 32 * 1024;
const SCAN_CACHE_KIB: i64 = 8 * 1024;

pub struct InsightDb {
    path: PathBuf,
    /// None when opened read-only.
    write: Option<Mutex<Connection>>,
    /// Short lookups by hash (every scan asks for a verdict).
    lookup: Mutex<Connection>,
}

/// One sighting row (see `ThreatInsight::sightings`).
pub struct SightingRow {
    pub ip: String,
    pub path: String,
    pub first_seen: String,
    pub last_seen: String,
    pub count: i64,
}

/// One record as written: the JSON and the columns copied from it.
pub struct InsightRow {
    pub sha: Sha,
    pub data: Vec<u8>,
    pub verdict: String,
    pub threat: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub seen_count: i64,
    pub sightings: Vec<SightingRow>,
}

type Res<T> = rusqlite::Result<T>;

fn tune(conn: &Connection, cache_kib: i64) -> Res<()> {
    conn.busy_timeout(Duration::from_secs(30))?;
    conn.pragma_update(None, "cache_size", -cache_kib)?;
    Ok(())
}

fn open_read(path: &Path, cache_kib: i64) -> Res<Connection> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    tune(&conn, cache_kib)?;
    Ok(conn)
}

fn has_column(conn: &Connection, table: &str, column: &str) -> Res<bool> {
    let mut st = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = st.query_map([], |r| r.get::<_, String>(1))?;
    for n in names {
        if n? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

impl InsightDb {
    /// Opens (creating when missing) the database for reading and writing.
    pub fn open(path: &Path) -> Res<Self> {
        let conn = Connection::open(path)?;
        tune(&conn, WRITE_CACHE_KIB)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS insights (
                 sha  BLOB PRIMARY KEY,
                 seq  INTEGER NOT NULL,
                 data BLOB NOT NULL
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS insights_seq ON insights(seq);
             CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS sightings (
                 sha        BLOB NOT NULL,
                 ip         TEXT NOT NULL,
                 path       TEXT NOT NULL,
                 first_seen TEXT NOT NULL,
                 last_seen  TEXT NOT NULL,
                 count      INTEGER NOT NULL,
                 PRIMARY KEY (sha, ip, path)
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS sightings_ip ON sightings(ip);",
        )?;
        // Columns added after the first SQLite version; existing rows get them from
        // `stale_rows` (their `cols_seq` is NULL).
        for (col, ty) in [
            ("verdict", "TEXT"),
            ("threat", "TEXT"),
            ("first_seen", "TEXT"),
            ("last_seen", "TEXT"),
            ("seen_count", "INTEGER"),
            ("cols_seq", "INTEGER"),
        ] {
            if !has_column(&conn, "insights", col)? {
                conn.execute_batch(&format!("ALTER TABLE insights ADD COLUMN {col} {ty}"))?;
            }
        }
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS insights_verdict ON insights(verdict);
             CREATE INDEX IF NOT EXISTS insights_first_seen ON insights(first_seen);",
        )?;
        let lookup = open_read(path, LOOKUP_CACHE_KIB)?;
        Ok(Self { path: path.to_path_buf(), write: Some(Mutex::new(conn)), lookup: Mutex::new(lookup) })
    }

    /// Opens an existing database for reading only (the standby's first look).
    pub fn open_readonly(path: &Path) -> Res<Self> {
        let lookup = open_read(path, SCAN_CACHE_KIB)?;
        Ok(Self { path: path.to_path_buf(), write: None, lookup: Mutex::new(lookup) })
    }

    fn writer(&self) -> Res<std::sync::MutexGuard<'_, Connection>> {
        self.write
            .as_ref()
            .map(|m| m.lock().unwrap())
            .ok_or(rusqlite::Error::InvalidQuery)
    }

    /// A short query on the shared lookup connection (one row by hash and the like).
    pub fn lookup<T>(&self, f: impl FnOnce(&Connection) -> Res<T>) -> Res<T> {
        f(&self.lookup.lock().unwrap())
    }

    /// A long read (walks many rows) on a connection of its own, so lookups by hash
    /// for scans and the writer do not wait for it.
    pub fn scan<T>(&self, f: impl FnOnce(&Connection) -> Res<T>) -> Res<T> {
        f(&open_read(&self.path, SCAN_CACHE_KIB)?)
    }

    pub fn count(&self) -> Res<u64> {
        self.lookup(|c| c.query_row("SELECT COUNT(*) FROM insights", [], |r| r.get::<_, i64>(0)).map(|n| n as u64))
    }

    /// Highest `seq` written so far (0 when empty).
    pub fn max_seq(&self) -> Res<i64> {
        self.lookup(|c| c.query_row("SELECT COALESCE(MAX(seq), 0) FROM insights", [], |r| r.get(0)))
    }

    /// The JSON of one hash.
    pub fn get(&self, sha: &Sha) -> Res<Option<Vec<u8>>> {
        self.lookup(|c| {
            let mut st = c.prepare_cached("SELECT data FROM insights WHERE sha = ?1")?;
            let mut rows = st.query([&sha[..]])?;
            match rows.next()? {
                Some(r) => Ok(Some(r.get(0)?)),
                None => Ok(None),
            }
        })
    }

    pub fn meta(&self, key: &str) -> Option<String> {
        self.lookup(|c| c.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))).ok()
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Res<()> {
        let c = self.writer()?;
        c.execute("INSERT INTO meta(key, value) VALUES(?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value", [key, value])?;
        Ok(())
    }

    /// Inserts or replaces the records in one transaction; each gets the next `seq`
    /// (read inside the transaction, so another process writing at the same time cannot
    /// hand out the same number).
    pub fn upsert_batch(&self, rows: &[InsightRow]) -> Res<()> {
        let mut c = self.writer()?;
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        {
            let mut seq: i64 = tx.query_row("SELECT COALESCE(MAX(seq), 0) FROM insights", [], |r| r.get(0))?;
            let mut st = tx.prepare_cached(
                "INSERT INTO insights(sha, seq, data, verdict, threat, first_seen, last_seen, seen_count, cols_seq)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?2)
                 ON CONFLICT(sha) DO UPDATE SET seq = excluded.seq, data = excluded.data,
                     verdict = excluded.verdict, threat = excluded.threat, first_seen = excluded.first_seen,
                     last_seen = excluded.last_seen, seen_count = excluded.seen_count, cols_seq = excluded.cols_seq",
            )?;
            for row in rows {
                seq += 1;
                st.execute(params![
                    &row.sha[..],
                    seq,
                    row.data,
                    row.verdict,
                    row.threat,
                    row.first_seen,
                    row.last_seen,
                    row.seen_count
                ])?;
                write_sightings(&tx, row)?;
            }
        }
        tx.commit()
    }

    /// Rows whose columns are missing or older than their JSON: `(sha, seq, json)`,
    /// at most `limit`, after `after` in hash order.
    pub fn stale_rows(&self, after: &Sha, limit: usize) -> Res<Vec<(Sha, i64, Vec<u8>)>> {
        self.scan(|c| {
            let mut st = c.prepare(
                "SELECT sha, seq, data FROM insights WHERE sha > ?1 AND cols_seq IS NOT seq ORDER BY sha LIMIT ?2",
            )?;
            let rows = st.query_map(params![&after[..], limit as i64], |r| {
                let sha: Vec<u8> = r.get(0)?;
                Ok((sha, r.get::<_, i64>(1)?, r.get::<_, Vec<u8>>(2)?))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (sha, seq, data) = row?;
                if let Ok(sha) = Sha::try_from(sha.as_slice()) {
                    out.push((sha, seq, data));
                }
            }
            Ok(out)
        })
    }

    /// Fills the columns of rows read by `stale_rows` without giving them a new `seq`
    /// (the record did not change). A row written again since then is left alone: its
    /// writer filled the columns. `None` = the JSON could not be read; the row is
    /// marked done so it is not read again every time.
    pub fn fill_columns(&self, rows: &[(i64, Sha, Option<InsightRow>)]) -> Res<()> {
        let mut c = self.writer()?;
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        {
            let mut st = tx.prepare_cached(
                "UPDATE insights SET verdict = ?3, threat = ?4, first_seen = ?5, last_seen = ?6, seen_count = ?7, cols_seq = ?2
                 WHERE sha = ?1 AND seq = ?2",
            )?;
            let mut done = tx.prepare_cached("UPDATE insights SET cols_seq = ?2 WHERE sha = ?1 AND seq = ?2")?;
            for (seq, sha, row) in rows {
                match row {
                    Some(row) => {
                        if st.execute(params![&sha[..], seq, row.verdict, row.threat, row.first_seen, row.last_seen, row.seen_count])? > 0 {
                            write_sightings(&tx, row)?;
                        }
                    }
                    None => {
                        done.execute(params![&sha[..], seq])?;
                    }
                }
            }
        }
        tx.commit()
    }

    /// Every record, in hash order.
    #[cfg(test)]
    pub fn for_each(&self, mut f: impl FnMut(Sha, &[u8])) -> Res<()> {
        self.scan(|c| {
            let mut st = c.prepare("SELECT sha, data FROM insights")?;
            let mut rows = st.query([])?;
            while let Some(row) = rows.next()? {
                let Ok(sha) = Sha::try_from(row.get_ref(0)?.as_blob()?) else { continue };
                f(sha, row.get_ref(1)?.as_blob()?);
            }
            Ok(())
        })
    }

    /// Records written after `seq`, oldest change first, at most `limit`:
    /// `(seq, json)`. The change feed for the archive mirror and the standby.
    pub fn changes_since(&self, seq: i64, limit: usize) -> Res<Vec<(i64, Vec<u8>)>> {
        self.scan(|c| {
            let mut st = c.prepare("SELECT seq, data FROM insights WHERE seq > ?1 ORDER BY seq LIMIT ?2")?;
            let rows = st.query_map(params![seq, limit as i64], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect()
        })
    }
}

fn write_sightings(tx: &Connection, row: &InsightRow) -> Res<()> {
    tx.prepare_cached("DELETE FROM sightings WHERE sha = ?1")?.execute([&row.sha[..]])?;
    let mut st = tx.prepare_cached(
        "INSERT OR REPLACE INTO sightings(sha, ip, path, first_seen, last_seen, count) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for s in &row.sightings {
        st.execute(params![&row.sha[..], s.ip, s.path, s.first_seen, s.last_seen, s.count])?;
    }
    Ok(())
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

    fn row(sha: Sha, data: &str, verdict: &str, sightings: &[(&str, &str)]) -> InsightRow {
        InsightRow {
            sha,
            data: data.as_bytes().to_vec(),
            verdict: verdict.into(),
            threat: None,
            first_seen: "2026-10-30T00:00:00+00:00".into(),
            last_seen: "2026-10-30T00:00:00+00:00".into(),
            seen_count: 1,
            sightings: sightings
                .iter()
                .map(|(ip, path)| SightingRow { ip: ip.to_string(), path: path.to_string(), first_seen: String::new(), last_seen: String::new(), count: 1 })
                .collect(),
        }
    }

    #[test]
    fn upsert_replaces_in_place_and_orders_changes() {
        let db = InsightDb::open(&tmp("upsert")).unwrap();
        let (a, b) = ([1u8; 32], [2u8; 32]);
        db.upsert_batch(&[row(a, "a1", "clean", &[]), row(b, "b1", "clean", &[])]).unwrap();
        db.upsert_batch(&[row(a, "a2", "malicious", &[])]).unwrap();
        assert_eq!(db.count().unwrap(), 2, "one row per hash");
        assert_eq!(db.max_seq().unwrap(), 3);
        let all = db.changes_since(0, 10).unwrap();
        assert_eq!(all, vec![(2, b"b1".to_vec()), (3, b"a2".to_vec())], "the replaced copy is gone, newest change last");
        assert_eq!(db.changes_since(2, 10).unwrap(), vec![(3, b"a2".to_vec())]);
        assert_eq!(db.get(&a).unwrap().as_deref(), Some(&b"a2"[..]));
        let v: String = db.lookup(|c| c.query_row("SELECT verdict FROM insights WHERE sha = ?1", [&a[..]], |r| r.get(0))).unwrap();
        assert_eq!(v, "malicious", "columns follow the record");
    }

    #[test]
    fn sightings_are_replaced_with_the_record() {
        let db = InsightDb::open(&tmp("sight")).unwrap();
        let a = [3u8; 32];
        db.upsert_batch(&[row(a, "x", "clean", &[("1.1.1.1", "C:\\a"), ("2.2.2.2", "")])]).unwrap();
        db.upsert_batch(&[row(a, "y", "clean", &[("1.1.1.1", "C:\\b")])]).unwrap();
        let n: i64 = db.lookup(|c| c.query_row("SELECT COUNT(*) FROM sightings WHERE sha = ?1", [&a[..]], |r| r.get(0))).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn rows_from_an_older_writer_are_found_and_filled() {
        let p = tmp("stale");
        let db = InsightDb::open(&p).unwrap();
        let a = [4u8; 32];
        db.upsert_batch(&[row(a, "x", "clean", &[])]).unwrap();
        assert!(db.stale_rows(&[0u8; 32], 10).unwrap().is_empty());
        // What a version without the columns writes: a new seq, columns untouched.
        db.writer().unwrap().execute("UPDATE insights SET seq = seq + 1, data = x'7a' WHERE sha = ?1", [&a[..]]).unwrap();
        let stale = db.stale_rows(&[0u8; 32], 10).unwrap();
        assert_eq!(stale.len(), 1);
        let (sha, seq, _) = &stale[0];
        db.fill_columns(&[(*seq, *sha, Some(row(a, "z", "malicious", &[("9.9.9.9", "")])))]).unwrap();
        assert!(db.stale_rows(&[0u8; 32], 10).unwrap().is_empty());
        let v: String = db.lookup(|c| c.query_row("SELECT verdict FROM insights WHERE sha = ?1", [&a[..]], |r| r.get(0))).unwrap();
        assert_eq!(v, "malicious");
    }

    #[test]
    fn for_each_returns_the_live_rows() {
        let db = InsightDb::open(&tmp("each")).unwrap();
        let a = [7u8; 32];
        db.upsert_batch(&[row(a, "x", "clean", &[])]).unwrap();
        db.upsert_batch(&[row(a, "y", "clean", &[])]).unwrap();
        let mut got = Vec::new();
        db.for_each(|s, d| got.push((s, d.to_vec()))).unwrap();
        assert_eq!(got, vec![(a, b"y".to_vec())]);
    }

    #[test]
    fn readonly_sees_what_the_writer_wrote() {
        let p = tmp("ro");
        let w = InsightDb::open(&p).unwrap();
        w.upsert_batch(&[row([9u8; 32], "z", "clean", &[])]).unwrap();
        let r = InsightDb::open_readonly(&p).unwrap();
        assert_eq!(r.max_seq().unwrap(), 1);
        w.upsert_batch(&[row([8u8; 32], "w", "clean", &[])]).unwrap();
        assert_eq!(r.changes_since(1, 10).unwrap().len(), 1);
        assert!(r.set_meta("k", "v").is_err(), "read-only");
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
