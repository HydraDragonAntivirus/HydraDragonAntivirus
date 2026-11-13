//! SQLite store of the EDR telemetry: every behavior, network flow and threat report
//! an endpoint sends, kept for good (nothing here deletes or prunes a row).
//!
//! `EdrTelemetryStore` keeps the newest records in memory for the live dashboard; this
//! is the full history behind it. It is read back at start (the newest records and the
//! totals), and searches and filters ask it instead of the in-memory window.
//!
//! Each table holds the stored record as JSON in `data` (its `id` is the row id) plus
//! the columns the dashboard filters on: `verdict`, and `search`, the lowercased
//! searchable fields joined by newlines, matched with `instr` the way the in-memory
//! filter matches with `contains`.

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{params, Connection, OpenFlags};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::edr_telemetry::{EdrStats, StoredBehavior, StoredFlow, StoredThreat};

type Res<T> = rusqlite::Result<T>;

const WRITE_CACHE_KIB: i64 = 16 * 1024;
const READ_CACHE_KIB: i64 = 8 * 1024;

pub struct EdrDb {
    write: Mutex<Connection>,
    read: Mutex<Connection>,
}

fn tune(conn: &Connection, cache_kib: i64) -> Res<()> {
    conn.busy_timeout(Duration::from_secs(30))?;
    conn.pragma_update(None, "cache_size", -cache_kib)?;
    Ok(())
}

fn to_json<T: Serialize>(v: &T) -> Res<String> {
    serde_json::to_string(v).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
}

fn from_json<T: DeserializeOwned>(text: &str) -> Option<T> {
    serde_json::from_str(text).ok()
}

/// The fields `EdrTelemetryStore::get_behaviors` searches, lowercased.
pub fn behavior_search_text(b: &StoredBehavior) -> String {
    [
        b.process_name.as_str(),
        b.exe_path.as_str(),
        b.command_line.as_str(),
        b.detection.as_str(),
        b.machine_id.as_str(),
        &b.pid.to_string(),
        b.sha256.as_str(),
    ]
    .join("\n")
    .to_lowercase()
}

/// The fields `EdrTelemetryStore::get_flows` searches, lowercased.
pub fn flow_search_text(f: &StoredFlow) -> String {
    [
        f.process_name.as_str(),
        f.src_ip.as_str(),
        f.dst_ip.as_str(),
        f.protocol.as_str(),
        f.machine_id.as_str(),
        f.hostname.as_deref().unwrap_or(""),
        &f.pid.to_string(),
    ]
    .join("\n")
    .to_lowercase()
}

/// Rows of `sql` (selecting `id, data`), newest first, decoded and given their row id.
fn query_rows<T: DeserializeOwned>(
    conn: &Connection,
    sql: &str,
    args: &[&dyn rusqlite::ToSql],
    set_id: impl Fn(&mut T, u64),
) -> Res<Vec<T>> {
    let mut st = conn.prepare_cached(sql)?;
    let rows = st.query_map(args, |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
    let mut out = Vec::new();
    for row in rows {
        let (id, data) = row?;
        if let Some(mut item) = from_json::<T>(&data) {
            set_id(&mut item, id as u64);
            out.push(item);
        }
    }
    Ok(out)
}

impl EdrDb {
    /// Opens (creating when missing) the database for reading and writing.
    pub fn open(path: &Path) -> Res<Self> {
        let conn = Connection::open(path)?;
        tune(&conn, WRITE_CACHE_KIB)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "journal_size_limit", crate::insight_db::WAL_SIZE_LIMIT)?;
        let _ = crate::insight_db::truncate_wal(&conn, Duration::from_secs(5));
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS behaviors (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 verdict TEXT NOT NULL,
                 search TEXT NOT NULL,
                 data TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS behaviors_verdict ON behaviors(verdict, id);
             CREATE TABLE IF NOT EXISTS flows (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 search TEXT NOT NULL,
                 data TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS threats (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 data TEXT NOT NULL
             );",
        )?;
        let read = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
        tune(&read, READ_CACHE_KIB)?;
        Ok(Self { write: Mutex::new(conn), read: Mutex::new(read) })
    }

    /// Writes `b` and returns its row id (the record's id).
    pub fn insert_behavior(&self, b: &StoredBehavior) -> Res<u64> {
        let conn = self.write.lock().unwrap_or_else(|e| e.into_inner());
        conn.prepare_cached("INSERT INTO behaviors (verdict, search, data) VALUES (?1, ?2, ?3)")?
            .execute(params![b.verdict.to_ascii_lowercase(), behavior_search_text(b), to_json(b)?])?;
        Ok(conn.last_insert_rowid() as u64)
    }

    /// Writes the flows in one transaction and sets each one's id to its row id.
    pub fn insert_flows(&self, flows: &mut [StoredFlow]) -> Res<()> {
        let mut conn = self.write.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        {
            let mut st = tx.prepare_cached("INSERT INTO flows (search, data) VALUES (?1, ?2)")?;
            for f in flows.iter_mut() {
                st.execute(params![flow_search_text(f), to_json(f)?])?;
                f.id = tx.last_insert_rowid() as u64;
            }
        }
        tx.commit()
    }

    /// Writes `t` and returns its row id (the record's id).
    pub fn insert_threat(&self, t: &StoredThreat) -> Res<u64> {
        let conn = self.write.lock().unwrap_or_else(|e| e.into_inner());
        conn.prepare_cached("INSERT INTO threats (data) VALUES (?1)")?.execute(params![to_json(t)?])?;
        Ok(conn.last_insert_rowid() as u64)
    }

    /// Totals over the whole history, counted the way `EdrTelemetryStore` counts them
    /// (any verdict other than malicious or suspicious is clean).
    pub fn stats(&self) -> Res<EdrStats> {
        let conn = self.read.lock().unwrap_or_else(|e| e.into_inner());
        let count = |verdict: &str| -> Res<u64> {
            conn.query_row("SELECT COUNT(*) FROM behaviors WHERE verdict = ?1", [verdict], |r| r.get::<_, i64>(0))
                .map(|n| n as u64)
        };
        let total = |table: &str| -> Res<u64> {
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get::<_, i64>(0)).map(|n| n as u64)
        };
        let total_behaviors = total("behaviors")?;
        let malicious_behaviors = count("malicious")?;
        let suspicious_behaviors = count("suspicious")?;
        Ok(EdrStats {
            total_behaviors,
            malicious_behaviors,
            suspicious_behaviors,
            clean_behaviors: total_behaviors.saturating_sub(malicious_behaviors + suspicious_behaviors),
            total_flows: total("flows")?,
            total_threats: total("threats")?,
        })
    }

    /// Newest behaviors first. `verdict` is lowercase; `search` is lowercase and not empty.
    pub fn behaviors(&self, limit: usize, verdict: Option<&str>, search: Option<&str>) -> Res<Vec<StoredBehavior>> {
        let conn = self.read.lock().unwrap_or_else(|e| e.into_inner());
        let limit = limit as i64;
        let set_id = |b: &mut StoredBehavior, id| b.id = id;
        match (verdict, search) {
            (Some(v), Some(q)) => query_rows(
                &conn,
                "SELECT id, data FROM behaviors WHERE verdict = ?1 AND instr(search, ?2) > 0 ORDER BY id DESC LIMIT ?3",
                &[&v, &q, &limit],
                set_id,
            ),
            (Some(v), None) => query_rows(
                &conn,
                "SELECT id, data FROM behaviors WHERE verdict = ?1 ORDER BY id DESC LIMIT ?2",
                &[&v, &limit],
                set_id,
            ),
            (None, Some(q)) => query_rows(
                &conn,
                "SELECT id, data FROM behaviors WHERE instr(search, ?1) > 0 ORDER BY id DESC LIMIT ?2",
                &[&q, &limit],
                set_id,
            ),
            (None, None) => {
                query_rows(&conn, "SELECT id, data FROM behaviors ORDER BY id DESC LIMIT ?1", &[&limit], set_id)
            }
        }
    }

    /// Newest flows first. `search` is lowercase and not empty.
    pub fn flows(&self, limit: usize, search: Option<&str>) -> Res<Vec<StoredFlow>> {
        let conn = self.read.lock().unwrap_or_else(|e| e.into_inner());
        let limit = limit as i64;
        let set_id = |f: &mut StoredFlow, id| f.id = id;
        match search {
            Some(q) => query_rows(
                &conn,
                "SELECT id, data FROM flows WHERE instr(search, ?1) > 0 ORDER BY id DESC LIMIT ?2",
                &[&q, &limit],
                set_id,
            ),
            None => query_rows(&conn, "SELECT id, data FROM flows ORDER BY id DESC LIMIT ?1", &[&limit], set_id),
        }
    }

    /// Newest threat reports first.
    pub fn threats(&self, limit: usize) -> Res<Vec<StoredThreat>> {
        let conn = self.read.lock().unwrap_or_else(|e| e.into_inner());
        let limit = limit as i64;
        query_rows(&conn, "SELECT id, data FROM threats ORDER BY id DESC LIMIT ?1", &[&limit], |t: &mut StoredThreat, id| {
            t.id = id
        })
    }
}
