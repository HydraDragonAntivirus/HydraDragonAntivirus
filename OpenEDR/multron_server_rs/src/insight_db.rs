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
const LOOKUP_CACHE_KIB: i64 = 16 * 1024;
const LOOKUP_CONNECTIONS: usize = 8;
const SCAN_CACHE_KIB: i64 = 8 * 1024;
const WAL_CHECKPOINT_PAGES: i64 = 10_000;
/// Size the `-wal` file is cut back to after a checkpoint has copied it into the
/// database. Without it the file never shrinks: it stays as large as its biggest
/// moment, which can be larger than the database itself.
pub(crate) const WAL_SIZE_LIMIT: i64 = 64 * 1024 * 1024;
/// How often the writer forces the WAL back to the start ([`truncate_wal`]).
const WAL_TRUNCATE_EVERY: Duration = Duration::from_secs(60);
const PAGE_SIZE: i64 = 16_384;
const UPGRADE_CACHE_KIB: i64 = 512 * 1024;
const INSIGHT_INDEXES: &str = "CREATE INDEX IF NOT EXISTS insights_seq ON insights(seq);
     CREATE INDEX IF NOT EXISTS insights_verdict ON insights(verdict, sha);
     CREATE INDEX IF NOT EXISTS insights_first_seen ON insights(first_seen);";

pub struct InsightDb {
    path: PathBuf,
    /// None when opened read-only.
    write: Option<Mutex<Connection>>,
    /// Short lookups by hash (every scan asks for a verdict).
    lookup: Vec<Mutex<Connection>>,
    /// When the writer last forced the WAL back to the start.
    last_truncate: Mutex<std::time::Instant>,
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

/// Copies the whole WAL into the database and cuts the `-wal` file to zero.
///
/// The automatic checkpoint is PASSIVE: it copies what it can but never waits, so
/// with lookups reading all the time the WAL is never rewound and keeps growing
/// (every write is appended at its end). TRUNCATE waits a moment for the readers
/// that still use the old frames; new readers then read the database file and do
/// not hold it up. Only frames already committed are moved, nothing is dropped.
/// Busy (a long read still running): the copied part stays copied, retried later.
pub(crate) fn truncate_wal(conn: &Connection, wait: Duration) -> Res<bool> {
    conn.busy_timeout(wait)?;
    let done = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get::<_, i64>(0)).map(|busy| busy == 0);
    conn.busy_timeout(Duration::from_secs(30))?;
    done
}

fn thread_slot() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    thread_local!(static SLOT: usize = NEXT.fetch_add(1, Ordering::Relaxed));
    SLOT.with(|s| *s)
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
        Self::open_with(path, false)
    }

    pub fn open_upgraded(path: &Path) -> Res<Self> {
        Self::open_with(path, true)
    }

    fn open_with(path: &Path, upgrade: bool) -> Res<Self> {
        let conn = Connection::open(path)?;
        tune(&conn, WRITE_CACHE_KIB)?;
        conn.pragma_update(None, "page_size", PAGE_SIZE)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "wal_autocheckpoint", WAL_CHECKPOINT_PAGES)?;
        conn.pragma_update(None, "journal_size_limit", WAL_SIZE_LIMIT)?;
        // A WAL left large by an earlier run is copied in and cut now, before the
        // lookups start reading.
        let _ = truncate_wal(&conn, Duration::from_secs(5));
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS insights (
                 sha        BLOB NOT NULL UNIQUE,
                 seq        INTEGER NOT NULL,
                 data       BLOB NOT NULL,
                 verdict    TEXT,
                 threat     TEXT,
                 first_seen TEXT,
                 last_seen  TEXT,
                 seen_count INTEGER,
                 cols_seq   INTEGER
             );
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
        conn.execute_batch(INSIGHT_INDEXES)?;
        if upgrade {
            upgrade_layout(&conn, path);
        }
        let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(1, LOOKUP_CONNECTIONS);
        let lookup = (0..n).map(|_| open_read(path, LOOKUP_CACHE_KIB).map(Mutex::new)).collect::<Res<Vec<_>>>()?;
        Ok(Self { path: path.to_path_buf(), write: Some(Mutex::new(conn)), lookup, last_truncate: Mutex::new(std::time::Instant::now()) })
    }

    /// Opens an existing database for reading only (the standby's first look).
    pub fn open_readonly(path: &Path) -> Res<Self> {
        let lookup = open_read(path, SCAN_CACHE_KIB)?;
        Ok(Self { path: path.to_path_buf(), write: None, lookup: vec![Mutex::new(lookup)], last_truncate: Mutex::new(std::time::Instant::now()) })
    }

    /// After a write: at most once a minute, the WAL is copied into the database and
    /// cut back ([`truncate_wal`]). Waits at most half a second for readers; the next
    /// write tries again when they did not finish.
    fn truncate_wal_if_due(&self, conn: &Connection) {
        let mut last = self.last_truncate.lock().unwrap();
        if last.elapsed() < WAL_TRUNCATE_EVERY {
            return;
        }
        if let Ok(true) = truncate_wal(conn, Duration::from_millis(500)) {
            *last = std::time::Instant::now();
        }
    }

    fn writer(&self) -> Res<std::sync::MutexGuard<'_, Connection>> {
        self.write
            .as_ref()
            .map(|m| m.lock().unwrap())
            .ok_or(rusqlite::Error::InvalidQuery)
    }

    /// A short query on the shared lookup connection (one row by hash and the like).
    pub fn lookup<T>(&self, f: impl FnOnce(&Connection) -> Res<T>) -> Res<T> {
        let n = self.lookup.len();
        let own = thread_slot() % n;
        for k in 0..n {
            if let Ok(c) = self.lookup[(own + k) % n].try_lock() {
                return f(&c);
            }
        }
        f(&self.lookup[own].lock().unwrap())
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
            let mut same_columns = tx.prepare_cached(
                "UPDATE insights SET seq = ?2, data = ?3, last_seen = ?7, seen_count = ?8, cols_seq = ?2
                 WHERE sha = ?1 AND verdict IS ?4 AND threat IS ?5 AND first_seen IS ?6",
            )?;
            let mut ordered: Vec<&InsightRow> = rows.iter().collect();
            ordered.sort_by_key(|r| r.sha);
            for row in ordered {
                seq += 1;
                let values = params![
                    &row.sha[..],
                    seq,
                    row.data,
                    row.verdict,
                    row.threat,
                    row.first_seen,
                    row.last_seen,
                    row.seen_count
                ];
                if same_columns.execute(values)? == 0 {
                    st.execute(values)?;
                }
                write_sightings(&tx, row)?;
            }
        }
        tx.commit()?;
        self.truncate_wal_if_due(&c);
        Ok(())
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
        tx.commit()?;
        self.truncate_wal_if_due(&c);
        Ok(())
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

fn widen_verdict_index(conn: &Connection) {
    let columns: i64 = conn.query_row("SELECT COUNT(*) FROM pragma_index_info('insights_verdict')", [], |r| r.get(0)).unwrap_or(2);
    if columns >= 2 {
        return;
    }
    let widened = conn.execute_batch(
        "BEGIN IMMEDIATE;
         DROP INDEX IF EXISTS insights_verdict;
         CREATE INDEX insights_verdict ON insights(verdict, sha);
         COMMIT;",
    );
    if let Err(e) = widened {
        let _ = conn.execute_batch("ROLLBACK");
        eprintln!("[telemetry] verdict index change failed: {e}");
    }
}

fn upgrade_layout(conn: &Connection, path: &Path) {
    let without_rowid = conn
        .query_row("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'insights'", [], |r| r.get::<_, String>(0))
        .map(|sql| sql.to_ascii_uppercase().contains("WITHOUT ROWID"))
        .unwrap_or(false);
    let page: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap_or(PAGE_SIZE);
    if !without_rowid {
        widen_verdict_index(conn);
    }
    if !without_rowid && page >= PAGE_SIZE {
        return;
    }
    let started = std::time::Instant::now();
    eprintln!("[telemetry] moving {} to the faster layout (once)", path.display());
    let _ = conn.pragma_update(None, "cache_size", -UPGRADE_CACHE_KIB);
    if without_rowid {
        let moved = conn.execute_batch(&format!(
            "BEGIN IMMEDIATE;
             CREATE TABLE insights_new (
                 sha        BLOB NOT NULL UNIQUE,
                 seq        INTEGER NOT NULL,
                 data       BLOB NOT NULL,
                 verdict    TEXT,
                 threat     TEXT,
                 first_seen TEXT,
                 last_seen  TEXT,
                 seen_count INTEGER,
                 cols_seq   INTEGER
             );
             INSERT INTO insights_new(sha, seq, data, verdict, threat, first_seen, last_seen, seen_count, cols_seq)
                 SELECT sha, seq, data, verdict, threat, first_seen, last_seen, seen_count, cols_seq FROM insights ORDER BY seq;
             DROP TABLE insights;
             ALTER TABLE insights_new RENAME TO insights;
             {INSIGHT_INDEXES}
             COMMIT;"
        ));
        if let Err(e) = moved {
            let _ = conn.execute_batch("ROLLBACK");
            eprintln!("[telemetry] layout change failed, keeping the old one: {e}");
            return;
        }
        eprintln!("[telemetry] table moved in {:.1} s", started.elapsed().as_secs_f64());
    }
    if page < PAGE_SIZE {
        let alone = conn.pragma_update_and_check(None, "journal_mode", "DELETE", |r| r.get::<_, String>(0)).map(|m| m.eq_ignore_ascii_case("delete")).unwrap_or(false);
        if alone {
            let vacuumed = conn.pragma_update(None, "page_size", PAGE_SIZE).and_then(|_| conn.execute_batch("VACUUM"));
            if let Err(e) = vacuumed {
                eprintln!("[telemetry] page size change failed, keeping {page}: {e}");
            }
        }
        if let Err(e) = conn.pragma_update(None, "journal_mode", "WAL") {
            eprintln!("[telemetry] journal_mode=WAL failed: {e}");
        }
    }
    let _ = conn.pragma_update(None, "cache_size", -WRITE_CACHE_KIB);
    eprintln!("[telemetry] layout ready in {:.1} s", started.elapsed().as_secs_f64());
}

fn write_sightings(tx: &Connection, row: &InsightRow) -> Res<()> {
    let mut stored: std::collections::HashMap<(String, String), (String, String, i64)> = std::collections::HashMap::new();
    {
        let mut read = tx.prepare_cached("SELECT ip, path, first_seen, last_seen, count FROM sightings WHERE sha = ?1")?;
        let rows = read.query_map([&row.sha[..]], |r| Ok(((r.get(0)?, r.get(1)?), (r.get(2)?, r.get(3)?, r.get(4)?))))?;
        for r in rows {
            let (key, value) = r?;
            stored.insert(key, value);
        }
    }
    let mut write = tx.prepare_cached(
        "INSERT INTO sightings(sha, ip, path, first_seen, last_seen, count) VALUES(?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(sha, ip, path) DO UPDATE SET first_seen = excluded.first_seen, last_seen = excluded.last_seen, count = excluded.count",
    )?;
    for s in &row.sightings {
        let unchanged = stored
            .remove(&(s.ip.clone(), s.path.clone()))
            .is_some_and(|(first, last, count)| first == s.first_seen && last == s.last_seen && count == s.count);
        if !unchanged {
            write.execute(params![&row.sha[..], s.ip, s.path, s.first_seen, s.last_seen, s.count])?;
        }
    }
    if !stored.is_empty() {
        let mut remove = tx.prepare_cached("DELETE FROM sightings WHERE sha = ?1 AND ip = ?2 AND path = ?3")?;
        for (ip, path) in stored.keys() {
            remove.execute(params![&row.sha[..], ip, path])?;
        }
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
    fn only_changed_sightings_are_written() {
        let db = InsightDb::open(&tmp("sight_diff")).unwrap();
        let a = [5u8; 32];
        let sighting = |ip: &str, last: &str, count: i64| SightingRow {
            ip: ip.into(),
            path: "C:\\x".into(),
            first_seen: "t0".into(),
            last_seen: last.into(),
            count,
        };
        let mut r = row(a, "x", "clean", &[]);
        r.sightings = vec![sighting("1.1.1.1", "t1", 1), sighting("2.2.2.2", "t1", 1), sighting("3.3.3.3", "t1", 1)];
        db.upsert_batch(&[r]).unwrap();
        let mut r = row(a, "y", "clean", &[]);
        r.sightings = vec![sighting("1.1.1.1", "t2", 2), sighting("2.2.2.2", "t1", 1), sighting("4.4.4.4", "t2", 1)];
        db.upsert_batch(&[r]).unwrap();
        let rows: Vec<(String, String, i64)> = db
            .lookup(|c| {
                let mut st = c.prepare("SELECT ip, last_seen, count FROM sightings WHERE sha = ?1 ORDER BY ip")?;
                let v = st.query_map([&a[..]], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect();
                v
            })
            .unwrap();
        assert_eq!(
            rows,
            vec![
                ("1.1.1.1".to_string(), "t2".to_string(), 2),
                ("2.2.2.2".to_string(), "t1".to_string(), 1),
                ("4.4.4.4".to_string(), "t2".to_string(), 1)
            ]
        );
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
    fn old_layout_is_moved_with_its_rows() {
        let p = tmp("upgrade");
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE insights (sha BLOB PRIMARY KEY, seq INTEGER NOT NULL, data BLOB NOT NULL) WITHOUT ROWID;
                 CREATE INDEX insights_seq ON insights(seq);",
            )
            .unwrap();
            c.execute("INSERT INTO insights(sha, seq, data) VALUES(?1, 1, x'61')", [&[1u8; 32][..]]).unwrap();
        }
        let db = InsightDb::open_upgraded(&p).unwrap();
        let sql: String = db.lookup(|c| c.query_row("SELECT sql FROM sqlite_master WHERE name = 'insights'", [], |r| r.get(0))).unwrap();
        assert!(!sql.to_ascii_uppercase().contains("WITHOUT ROWID"));
        let page: i64 = db.lookup(|c| c.query_row("PRAGMA page_size", [], |r| r.get(0))).unwrap();
        assert_eq!(page, PAGE_SIZE);
        let mode: String = db.lookup(|c| c.query_row("PRAGMA journal_mode", [], |r| r.get(0))).unwrap();
        assert_eq!(mode, "wal");
        assert_eq!(db.get(&[1u8; 32]).unwrap().as_deref(), Some(&b"a"[..]));
        assert_eq!(db.stale_rows(&[0u8; 32], 10).unwrap().len(), 1, "columns are still filled later");
        db.upsert_batch(&[row([1u8; 32], "b", "clean", &[]), row([2u8; 32], "c", "clean", &[])]).unwrap();
        assert_eq!(db.count().unwrap(), 2);
        assert_eq!(db.max_seq().unwrap(), 3);
    }

    #[test]
    fn verdict_index_covers_the_hash() {
        let p = tmp("verdict_index");
        {
            let db = InsightDb::open(&p).unwrap();
            db.upsert_batch(&[row([1u8; 32], "a", "malicious", &[])]).unwrap();
            db.writer().unwrap().execute_batch("DROP INDEX insights_verdict; CREATE INDEX insights_verdict ON insights(verdict);").unwrap();
        }
        let db = InsightDb::open_upgraded(&p).unwrap();
        let plan: String = db
            .lookup(|c| c.query_row("EXPLAIN QUERY PLAN SELECT sha, verdict FROM insights INDEXED BY insights_verdict WHERE verdict IN ('malicious')", [], |r| r.get(3)))
            .unwrap();
        assert!(plan.contains("COVERING INDEX insights_verdict"), "{plan}");
    }

    #[test]
    fn wal_is_cut_back_after_writes() {
        let p = tmp("wal_cut");
        let db = InsightDb::open(&p).unwrap();
        let big = "x".repeat(4000);
        let rows: Vec<InsightRow> = (0..500u32)
            .map(|i| {
                let mut sha = [0u8; 32];
                sha[..4].copy_from_slice(&i.to_be_bytes());
                row(sha, &big, "clean", &[])
            })
            .collect();
        // A lookup connection has read (and keeps its cached statement): the case where
        // the passive autocheckpoint never rewinds the WAL.
        assert_eq!(db.count().unwrap(), 0);
        db.upsert_batch(&rows).unwrap();
        let wal = std::path::PathBuf::from(format!("{}-wal", p.display()));
        assert!(std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0) > 0);
        *db.last_truncate.lock().unwrap() -= WAL_TRUNCATE_EVERY;
        db.upsert_batch(&rows[..1]).unwrap();
        assert_eq!(std::fs::metadata(&wal).unwrap().len(), 0);
        assert_eq!(db.count().unwrap(), 500);
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
