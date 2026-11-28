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

use std::borrow::Cow;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, params, params_from_iter, types::Value as SqlValue};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::edr_telemetry::{
    EdrStats, StoredBehavior, StoredEdrEvent, StoredFlow, StoredKillchainEvent, StoredSystemReport,
    StoredThreat,
};

type Res<T> = rusqlite::Result<T>;

/// One kill chain event a machine uploaded in full.
pub struct KillchainRow {
    pub key: String,
    pub count: u64,
    /// The stored event (an edrsvc log line).
    pub data: String,
    /// The machine's date (`YYYYMMDD`) and time of day of its first occurrence.
    pub date: String,
    pub time: String,
    pub event_type: String,
    pub exe: String,
    pub search: String,
}

const WRITE_CACHE_KIB: i64 = 16 * 1024;
const READ_CACHE_KIB: i64 = 8 * 1024;

pub struct EdrDb {
    path: PathBuf,
    write: Mutex<Connection>,
    read: Mutex<Connection>,
}

fn tune(conn: &Connection, cache_kib: i64) -> Res<()> {
    conn.busy_timeout(Duration::from_secs(30))?;
    conn.pragma_update(None, "cache_size", -cache_kib)?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
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
        f.dns_query.as_deref().unwrap_or(""),
        f.url.as_deref().unwrap_or(""),
        f.http_method.as_deref().unwrap_or(""),
        f.ja3.as_deref().unwrap_or(""),
        f.ja3s.as_deref().unwrap_or(""),
        &f.pid.to_string(),
    ]
    .join("\n")
    .to_lowercase()
}

fn push_json_str(parts: &mut Vec<String>, root: &serde_json::Value, path: &[&str]) {
    let mut cur = root;
    for seg in path {
        let Some(next) = cur.get(*seg) else {
            return;
        };
        cur = next;
    }
    if let Some(s) = cur.as_str() {
        if !s.is_empty() && s != "<undefined>" {
            parts.push(s.to_string());
        }
    } else if let Some(n) = cur.as_u64() {
        parts.push(n.to_string());
    }
}

const RAW_SEARCH_PATHS: &[&[&str]] = &[
    &["file", "path"],
    &["file", "rawPath"],
    &["file", "abstractPath"],
    &["file", "renameTarget"],
    &["file", "newPath"],
    &["file", "sha1"],
    &["file", "sha256"],
    &["file", "hash"],
    &["file_path"],
    &["hashes", "md5"],
    &["hashes", "sha1"],
    &["hashes", "sha256"],
    &["hashes", "imphash"],
    &["target", "pid"],
    &["target", "path"],
    &["target", "imageFile", "path"],
    &["target", "cmdLine"],
    &["childProcess", "imageFile", "path"],
    &["childProcess", "cmdLine"],
    &["process", "cmdLine"],
    &["process", "imageFile", "abstractPath"],
    &["process", "imageFile", "rawPath"],
    &["process", "imageFile", "sha1"],
    &["process", "imageFile", "hash"],
    &["registry", "path"],
    &["registry", "abstractPath"],
    &["registry", "rawPath"],
    &["registry", "name"],
    &["registry", "valueName"],
    &["registry_path"],
    &["owlyHook", "functionName"],
    &["network", "destinationAddress"],
    &["pipe", "name"],
    &["pipe_name"],
    &["scriptContent"],
    &["script_block"],
    &["ScriptBlockText"],
    &["Path"],
    &["service_name"],
    &["task_name"],
    &["TaskName"],
    &["account_name"],
    &["TargetUserName"],
    &["driver_path"],
    &["device_path"],
    &["device_object"],
    &["shadow_id"],
    &["url"],
    &["hostname"],
    &["QueryName"],
    &["ja3"],
    &["ja3s"],
    &["technique"],
    &["reason"],
    &["binding"],
    &["query"],
    &["kernelStackSymbols"],
];

fn finalize_search_text(parts: &[String]) -> String {
    let mut joined = parts.join("\n").to_lowercase();
    if joined.len() > 4096 {
        let mut end = 4096;
        while end > 0 && !joined.is_char_boundary(end) {
            end -= 1;
        }
        joined.truncate(end);
    }
    joined
}

/// The fields `EdrTelemetryStore::get_edr_events` searches, lowercased.
pub fn edr_event_search_text(e: &StoredEdrEvent) -> String {
    let mut parts = vec![
        e.event_type.clone(),
        e.machine_id.clone(),
        e.process_name.clone(),
        e.exe_path.clone(),
        e.pid.to_string(),
    ];
    if let Some(ref d) = e.details {
        if !d.is_empty() {
            parts.push(d.clone());
        }
    }
    for p in RAW_SEARCH_PATHS {
        push_json_str(&mut parts, &e.raw, p);
    }
    finalize_search_text(&parts)
}

/// Searchable lowercased index text for a kill chain event shape.
pub fn killchain_search_text(
    key: &str,
    machine_id: &str,
    exe: &str,
    event_type: &str,
    details: &str,
    raw: &serde_json::Value,
) -> String {
    let mut parts = vec![
        key.to_string(),
        machine_id.to_string(),
        exe.to_string(),
        event_type.to_string(),
    ];
    if !details.is_empty() {
        parts.push(details.to_string());
    }
    for p in RAW_SEARCH_PATHS {
        push_json_str(&mut parts, raw, p);
    }
    finalize_search_text(&parts)
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
        conn.pragma_update(
            None,
            "journal_size_limit",
            crate::insight_db::WAL_SIZE_LIMIT,
        )?;
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
             );
             CREATE TABLE IF NOT EXISTS killchain_events (
                 key TEXT PRIMARY KEY,
                 count INTEGER NOT NULL,
                 first_seen TEXT NOT NULL,
                 last_seen TEXT NOT NULL,
                 data TEXT NOT NULL,
                 event_type TEXT NOT NULL DEFAULT '',
                 exe TEXT NOT NULL DEFAULT '',
                 search TEXT NOT NULL DEFAULT ''
             );
             CREATE TABLE IF NOT EXISTS killchain_machines (
                 key TEXT NOT NULL,
                 machine TEXT NOT NULL,
                 PRIMARY KEY (key, machine)
             ) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS edr_events (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 timestamp INTEGER NOT NULL,
                 time_iso TEXT NOT NULL,
                 machine_id TEXT NOT NULL,
                 event_type TEXT NOT NULL,
                 pid INTEGER NOT NULL,
                 process_name TEXT NOT NULL,
                 exe_path TEXT NOT NULL,
                 search TEXT NOT NULL,
                 data TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS edr_events_type_id ON edr_events(event_type, id DESC);
             CREATE INDEX IF NOT EXISTS edr_events_machine_id ON edr_events(machine_id, id DESC);
             CREATE TABLE IF NOT EXISTS system_reports (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 machine_id TEXT NOT NULL,
                 time_iso TEXT NOT NULL,
                 data TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS system_reports_machine_id ON system_reports(machine_id, id DESC);",
        )?;
        // Per machine: how often it saw the event, when it uploaded it, and the
        // machine's own time of its first occurrence (the order of its kill
        // chain). Added to an existing table in place; rows from before have
        // count 0 and no times (only the merged count existed then).
        let have: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('killchain_machines')")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<_, _>>()?;
        for (col, decl) in [
            ("count", "INTEGER NOT NULL DEFAULT 0"),
            ("first_seen", "TEXT"),
            ("last_seen", "TEXT"),
            ("event_date", "TEXT"),
            ("event_time", "TEXT"),
        ] {
            if !have.iter().any(|c| c == col) {
                conn.execute_batch(&format!(
                    "ALTER TABLE killchain_machines ADD COLUMN {col} {decl}"
                ))?;
            }
        }
        let have_kc: Vec<String> = conn
            .prepare("SELECT name FROM pragma_table_info('killchain_events')")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<_, _>>()?;
        for (col, decl) in [
            ("event_type", "TEXT NOT NULL DEFAULT ''"),
            ("exe", "TEXT NOT NULL DEFAULT ''"),
            ("search", "TEXT NOT NULL DEFAULT ''"),
        ] {
            if !have_kc.iter().any(|c| c == col) {
                conn.execute_batch(&format!(
                    "ALTER TABLE killchain_events ADD COLUMN {col} {decl}"
                ))?;
            }
        }
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS killchain_machines_machine ON killchain_machines(machine);
             CREATE INDEX IF NOT EXISTS killchain_events_first_seen_key ON killchain_events(first_seen, key);
             CREATE INDEX IF NOT EXISTS killchain_events_last_seen_key ON killchain_events(last_seen DESC, key DESC);
             CREATE INDEX IF NOT EXISTS killchain_events_type_last ON killchain_events(event_type, last_seen DESC);
             CREATE INDEX IF NOT EXISTS killchain_events_count ON killchain_events(count);
             CREATE INDEX IF NOT EXISTS killchain_machines_summary ON killchain_machines(machine, count, first_seen, last_seen);
             CREATE INDEX IF NOT EXISTS killchain_machines_order ON killchain_machines(machine, event_date, event_time, key);",
        )?;
        let read = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        tune(&read, READ_CACHE_KIB)?;
        Ok(Self {
            path: path.to_path_buf(),
            write: Mutex::new(conn),
            read: Mutex::new(read),
        })
    }

    /// Opens an independent read-only WAL connection so bulk streaming exports never block live queries.
    pub fn open_readonly(&self) -> Res<Connection> {
        let conn = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        tune(&conn, WRITE_CACHE_KIB)?;
        conn.pragma_update(None, "query_only", "ON")?;
        Ok(conn)
    }

    /// Writes `b` and returns its row id (the record's id).
    pub fn insert_behavior(&self, b: &StoredBehavior) -> Res<u64> {
        let conn = self.write.lock().unwrap_or_else(|e| e.into_inner());
        conn.prepare_cached("INSERT INTO behaviors (verdict, search, data) VALUES (?1, ?2, ?3)")?
            .execute(params![
                b.verdict.to_ascii_lowercase(),
                behavior_search_text(b),
                to_json(b)?
            ])?;
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
        conn.prepare_cached("INSERT INTO threats (data) VALUES (?1)")?
            .execute(params![to_json(t)?])?;
        Ok(conn.last_insert_rowid() as u64)
    }

    /// Writes raw lossless EDR events in a single transaction and sets each one's row id.
    pub fn insert_edr_events(&self, events: &mut [StoredEdrEvent]) -> Res<()> {
        if events.is_empty() {
            return Ok(());
        }
        let mut conn = self.write.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        {
            let mut st = tx.prepare_cached(
                "INSERT INTO edr_events (timestamp, time_iso, machine_id, event_type, pid, process_name, exe_path, search, data)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            for ev in events.iter_mut() {
                st.execute(params![
                    ev.timestamp as i64,
                    ev.time_iso,
                    ev.machine_id,
                    ev.event_type,
                    ev.pid as i64,
                    ev.process_name,
                    ev.exe_path,
                    edr_event_search_text(ev),
                    to_json(ev)?,
                ])?;
                ev.id = tx.last_insert_rowid() as u64;
            }
        }
        tx.commit()
    }

    /// Writes a system diagnostic report and returns its row id.
    pub fn insert_system_report(&self, r: &StoredSystemReport) -> Res<u64> {
        let conn = self.write.lock().unwrap_or_else(|e| e.into_inner());
        conn.prepare_cached(
            "INSERT INTO system_reports (machine_id, time_iso, data) VALUES (?1, ?2, ?3)",
        )?
        .execute(params![r.machine_id, r.time_iso, to_json(r)?])?;
        Ok(conn.last_insert_rowid() as u64)
    }

    /// Merges a kill chain upload: a new key is stored with its first event (`data`, the
    /// edrsvc log line the trainer reads); a known key only gets its count raised (the
    /// first event is kept). `counts` raises the count of keys sent earlier.
    /// Returns `(new keys, merged keys, added_events)`.
    pub fn merge_killchain(
        &self,
        machine_id: &str,
        now: &str,
        records: &[KillchainRow],
        counts: &[(String, u64)],
    ) -> Res<(u64, u64, u64)> {
        let mut conn = self.write.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let (mut new, mut merged, mut added_events) = (0u64, 0u64, 0u64);
        {
            let mut ins = tx.prepare_cached(
                "INSERT INTO killchain_events (key, count, first_seen, last_seen, data, event_type, exe, search)
                 VALUES (?1, ?2, ?3, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(key) DO UPDATE SET
                     count = count + excluded.count,
                     last_seen = excluded.last_seen,
                     event_type = CASE WHEN event_type = '' THEN excluded.event_type ELSE event_type END,
                     exe = CASE WHEN exe = '' THEN excluded.exe ELSE exe END,
                     search = CASE WHEN search = '' THEN excluded.search ELSE search END",
            )?;
            let mut exists = tx.prepare_cached("SELECT 1 FROM killchain_events WHERE key = ?1")?;
            // The machine's own first occurrence (event_date/time) is set once;
            // a repeat only raises its count.
            let mut machine = tx.prepare_cached(
                "INSERT INTO killchain_machines (key, machine, count, first_seen, last_seen, event_date, event_time)
                 VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?6)
                 ON CONFLICT(key, machine) DO UPDATE SET
                     count = count + excluded.count,
                     last_seen = excluded.last_seen,
                     first_seen = COALESCE(first_seen, excluded.first_seen),
                     event_date = COALESCE(event_date, excluded.event_date),
                     event_time = COALESCE(event_time, excluded.event_time)",
            )?;
            for r in records {
                if exists.exists([&r.key])? {
                    merged += 1;
                } else {
                    new += 1;
                }
                added_events = added_events.saturating_add(r.count);
                ins.execute(params![
                    r.key,
                    r.count as i64,
                    now,
                    r.data,
                    r.event_type,
                    r.exe,
                    r.search
                ])?;
                machine.execute(params![
                    r.key,
                    machine_id,
                    r.count as i64,
                    now,
                    r.date,
                    r.time
                ])?;
            }
            let mut bump = tx.prepare_cached(
                "UPDATE killchain_events SET count = count + ?2, last_seen = ?3 WHERE key = ?1",
            )?;
            for (key, count) in counts {
                if bump.execute(params![key, *count as i64, now])? > 0 {
                    added_events = added_events.saturating_add(*count);
                    machine.execute(params![
                        key,
                        machine_id,
                        *count as i64,
                        now,
                        None::<String>,
                        None::<String>
                    ])?;
                }
            }
        }
        tx.commit()?;
        Ok((new, merged, added_events))
    }

    /// (distinct kill chain event shapes, events they stand for).
    pub fn killchain_totals(&self) -> Res<(u64, u64)> {
        let conn = self.read.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(count), 0) FROM killchain_events",
            [],
            |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
        )
    }

    /// Recent/filtered kill chain event shapes for dashboard browsing and inspection.
    pub fn killchain_records(
        &self,
        limit: usize,
        machine: Option<&str>,
        event_type: Option<&str>,
        search: Option<&str>,
    ) -> Res<Vec<StoredKillchainEvent>> {
        let conn = self.read.lock().unwrap_or_else(|e| e.into_inner());
        let mut conds: Vec<String> = Vec::new();
        let mut args: Vec<SqlValue> = Vec::new();
        let mach_clean = machine.map(str::trim).filter(|s| !s.is_empty());
        if let Some(m) = mach_clean {
            args.push(SqlValue::Text(m.to_string()));
            conds.push(format!("m.machine = ?{}", args.len()));
        }
        append_killchain_conds(&mut conds, &mut args, event_type, search, "k");
        args.push(SqlValue::Integer(limit as i64));
        let limit_idx = args.len();
        let where_sql = if conds.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conds.join(" AND "))
        };
        let mut out = Vec::new();
        if let Some(m) = mach_clean {
            let sql = format!(
                "SELECT k.key, m.count, k.count, COALESCE(m.first_seen, k.first_seen),
                        COALESCE(m.last_seen, k.last_seen), m.event_date, m.event_time, k.data
                 FROM killchain_machines m
                 JOIN killchain_events k ON k.key = m.key
                 {where_sql}
                 ORDER BY m.event_date DESC, m.event_time DESC, m.key DESC
                 LIMIT ?{limit_idx}"
            );
            let mut st = conn.prepare(&sql)?;
            let mut rows = st.query(params_from_iter(args))?;
            while let Some(r) = rows.next()? {
                let key: String = r.get(0)?;
                let m_count = r.get::<_, i64>(1)? as u64;
                let k_count = r.get::<_, i64>(2)? as u64;
                let first_seen: String = r.get::<_, Option<String>>(3)?.unwrap_or_default();
                let last_seen: String = r.get::<_, Option<String>>(4)?.unwrap_or_default();
                let event_date: Option<String> = r.get(5)?;
                let event_time: Option<String> = r.get(6)?;
                let data: String = r.get(7)?;
                if let Some(ev) = decode_killchain_record(
                    key,
                    m_count,
                    Some(k_count),
                    None,
                    first_seen,
                    last_seen,
                    event_date,
                    event_time,
                    Some(m),
                    &data,
                ) {
                    out.push(ev);
                }
            }
        } else {
            let sql = format!(
                "SELECT k.key, k.count, (SELECT COUNT(*) FROM killchain_machines m WHERE m.key = k.key),
                        k.first_seen, k.last_seen, k.data
                 FROM killchain_events k
                 {where_sql}
                 ORDER BY k.last_seen DESC, k.key DESC
                 LIMIT ?{limit_idx}"
            );
            let mut st = conn.prepare(&sql)?;
            let mut rows = st.query(params_from_iter(args))?;
            while let Some(r) = rows.next()? {
                let key: String = r.get(0)?;
                let k_count = r.get::<_, i64>(1)? as u64;
                let machines = r.get::<_, i64>(2)? as u64;
                let first_seen: String = r.get(3)?;
                let last_seen: String = r.get(4)?;
                let data: String = r.get(5)?;
                if let Some(ev) = decode_killchain_record(
                    key,
                    k_count,
                    None,
                    Some(machines),
                    first_seen,
                    last_seen,
                    None,
                    None,
                    None,
                    &data,
                ) {
                    out.push(ev);
                }
            }
        }
        Ok(out)
    }

    /// Streams kill chain events as NDJSON lines over a dedicated read-only connection,
    /// avoiding DOM re-parsing per row and never blocking live queries on `self.read`.
    pub fn stream_export_killchain<F>(
        &self,
        machine: Option<&str>,
        event_type: Option<&str>,
        search: Option<&str>,
        limit: Option<usize>,
        mut on_line: F,
    ) -> Res<u64>
    where
        F: FnMut(&[u8]) -> Result<(), ()>,
    {
        let conn = self.open_readonly()?;
        let mut conds: Vec<String> = Vec::new();
        let mut args: Vec<SqlValue> = Vec::new();
        let mach_clean = machine.map(str::trim).filter(|s| !s.is_empty());
        if let Some(m) = mach_clean {
            args.push(SqlValue::Text(m.to_string()));
            conds.push(format!("m.machine = ?{}", args.len()));
        }
        append_killchain_conds(&mut conds, &mut args, event_type, search, "k");
        let limit_sql = match limit.filter(|&n| n > 0) {
            Some(lim) => {
                args.push(SqlValue::Integer(lim as i64));
                format!("LIMIT ?{}", args.len())
            }
            None => String::new(),
        };
        let where_sql = if conds.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conds.join(" AND "))
        };
        let mut line_buf = Vec::with_capacity(8192);
        let mut n = 0u64;

        if let Some(m) = mach_clean {
            #[derive(Deserialize)]
            struct StoredKcLine<'a> {
                #[serde(borrow, default)]
                date: Cow<'a, str>,
                #[serde(borrow, default)]
                time: Cow<'a, str>,
                #[serde(borrow, default)]
                exe: Cow<'a, str>,
                #[serde(borrow, default)]
                event: Cow<'a, str>,
                #[serde(borrow, default)]
                details: Cow<'a, str>,
                #[serde(borrow)]
                raw: Option<&'a serde_json::value::RawValue>,
            }
            #[derive(Serialize)]
            struct ExportKcMachineLine<'a> {
                date: &'a str,
                time: &'a str,
                exe: &'a str,
                event: &'a str,
                details: &'a str,
                raw: &'a serde_json::value::RawValue,
                machine_id: &'a str,
                key: &'a str,
                count: i64,
                count_all: i64,
            }

            let sql = format!(
                "SELECT k.key, m.count, k.count, m.event_date, m.event_time, k.data
                 FROM killchain_machines m JOIN killchain_events k ON k.key = m.key
                 {where_sql}
                 ORDER BY m.event_date, m.event_time, m.key {limit_sql}"
            );
            let mut st = conn.prepare(&sql)?;
            let mut rows = st.query(params_from_iter(args))?;
            while let Some(r) = rows.next()? {
                let key: String = r.get(0)?;
                let m_count: i64 = r.get(1)?;
                let k_count: i64 = r.get(2)?;
                let d_opt: Option<String> = r.get(3)?;
                let t_opt: Option<String> = r.get(4)?;
                let data: String = r.get(5)?;
                line_buf.clear();
                let encoded = if let Ok(parsed) = serde_json::from_str::<StoredKcLine>(&data) {
                    if let Some(raw_val) = parsed.raw {
                        let line = ExportKcMachineLine {
                            date: d_opt.as_deref().unwrap_or(parsed.date.as_ref()),
                            time: t_opt.as_deref().unwrap_or(parsed.time.as_ref()),
                            exe: parsed.exe.as_ref(),
                            event: parsed.event.as_ref(),
                            details: parsed.details.as_ref(),
                            raw: raw_val,
                            machine_id: m,
                            key: &key,
                            count: m_count,
                            count_all: k_count,
                        };
                        serde_json::to_writer(&mut line_buf, &line).is_ok()
                    } else {
                        false
                    }
                } else {
                    false
                };
                if !encoded {
                    let Ok(serde_json::Value::Object(mut obj)) =
                        serde_json::from_str::<serde_json::Value>(&data)
                    else {
                        continue;
                    };
                    if let Some(d) = d_opt {
                        obj.insert("date".into(), d.into());
                    }
                    if let Some(t) = t_opt {
                        obj.insert("time".into(), t.into());
                    }
                    obj.insert("machine_id".into(), m.into());
                    obj.insert("key".into(), key.into());
                    obj.insert("count".into(), m_count.into());
                    obj.insert("count_all".into(), k_count.into());
                    if serde_json::to_writer(&mut line_buf, &obj).is_err() {
                        continue;
                    }
                }
                line_buf.push(b'\n');
                if on_line(&line_buf).is_err() {
                    return Ok(n);
                }
                n += 1;
            }
        } else {
            let sql = format!(
                "SELECT k.key, k.count, (SELECT COUNT(*) FROM killchain_machines m WHERE m.key = k.key), k.data
                 FROM killchain_events k {where_sql}
                 ORDER BY k.first_seen, k.key {limit_sql}"
            );
            let mut st = conn.prepare(&sql)?;
            let mut rows = st.query(params_from_iter(args))?;
            while let Some(r) = rows.next()? {
                let key: String = r.get(0)?;
                let count: i64 = r.get(1)?;
                let machines: i64 = r.get(2)?;
                let data: String = r.get(3)?;
                line_buf.clear();
                let trimmed = data.trim();
                let fast_ok = if trimmed.starts_with('{') && trimmed.ends_with('}') {
                    let prefix = &trimmed[..trimmed.len() - 1];
                    line_buf.extend_from_slice(prefix.as_bytes());
                    if prefix[1..].trim().is_empty() {
                        line_buf.extend_from_slice(br#""key":"#);
                    } else {
                        line_buf.extend_from_slice(br#","key":"#);
                    }
                    serde_json::to_writer(&mut line_buf, &key).is_ok()
                        && write!(&mut line_buf, r#","count":{count},"machines":{machines}}}"#)
                            .is_ok()
                } else {
                    false
                };
                if !fast_ok {
                    line_buf.clear();
                    let Ok(serde_json::Value::Object(mut obj)) =
                        serde_json::from_str::<serde_json::Value>(&data)
                    else {
                        continue;
                    };
                    obj.insert("key".into(), key.into());
                    obj.insert("count".into(), count.into());
                    obj.insert("machines".into(), machines.into());
                    if serde_json::to_writer(&mut line_buf, &obj).is_err() {
                        continue;
                    }
                }
                line_buf.push(b'\n');
                if on_line(&line_buf).is_err() {
                    return Ok(n);
                }
                n += 1;
            }
        }
        Ok(n)
    }

    /// Every stored kill chain event as JSON lines in edrsvc's log format (what
    /// train_kc_hybrid.py reads), each with its `count`, `machines` and `key`.
    #[allow(dead_code)]
    pub fn export_killchain(&self, out: &mut Vec<u8>) -> Res<u64> {
        self.stream_export_killchain(None, None, None, None, |line| {
            out.extend_from_slice(line);
            Ok(())
        })
    }

    /// One machine's kill chain as JSON lines, in the order it happened there
    /// (the machine's own date/time of each event's first occurrence).
    #[allow(dead_code)]
    pub fn export_killchain_machine(&self, machine: &str, out: &mut Vec<u8>) -> Res<u64> {
        self.stream_export_killchain(Some(machine), None, None, None, |line| {
            out.extend_from_slice(line);
            Ok(())
        })
    }

    /// Machines that uploaded kill chain events: (machine, distinct events,
    /// events counted, first upload, last upload), most recent first.
    pub fn killchain_machines(
        &self,
    ) -> Res<Vec<(String, u64, u64, Option<String>, Option<String>)>> {
        let conn = self.read.lock().unwrap_or_else(|e| e.into_inner());
        let mut st = conn.prepare(
            "SELECT machine, COUNT(*), COALESCE(SUM(count), 0), MIN(first_seen), MAX(last_seen)
             FROM killchain_machines GROUP BY machine ORDER BY MAX(last_seen) DESC, machine",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, i64>(2)? as u64,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })?;
        rows.collect()
    }

    /// Totals over the whole history, counted the way `EdrTelemetryStore` counts them
    /// (any verdict other than malicious or suspicious is clean).
    pub fn stats(&self) -> Res<EdrStats> {
        let conn = self.read.lock().unwrap_or_else(|e| e.into_inner());
        let count = |verdict: &str| -> Res<u64> {
            conn.query_row(
                "SELECT COUNT(*) FROM behaviors WHERE verdict = ?1",
                [verdict],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as u64)
        };
        let total = |table: &str| -> Res<u64> {
            conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| {
                r.get::<_, i64>(0)
            })
            .map(|n| n as u64)
        };
        let total_behaviors = total("behaviors")?;
        let malicious_behaviors = count("malicious")?;
        let suspicious_behaviors = count("suspicious")?;
        let total_sysops = conn
            .query_row(
                "SELECT COUNT(*) FROM edr_events WHERE event_type GLOB 'AGENT_*'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as u64)?;
        Ok(EdrStats {
            total_behaviors,
            malicious_behaviors,
            suspicious_behaviors,
            clean_behaviors: total_behaviors
                .saturating_sub(malicious_behaviors + suspicious_behaviors),
            total_flows: total("flows")?,
            total_threats: total("threats")?,
            total_events: total("edr_events")?,
            total_sysops,
            total_system_reports: total("system_reports")?,
        })
    }

    /// Newest behaviors first. `verdict` is lowercase; `search` is lowercase and not empty.
    pub fn behaviors(
        &self,
        limit: usize,
        verdict: Option<&str>,
        search: Option<&str>,
    ) -> Res<Vec<StoredBehavior>> {
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
            (None, None) => query_rows(
                &conn,
                "SELECT id, data FROM behaviors ORDER BY id DESC LIMIT ?1",
                &[&limit],
                set_id,
            ),
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
            None => query_rows(
                &conn,
                "SELECT id, data FROM flows ORDER BY id DESC LIMIT ?1",
                &[&limit],
                set_id,
            ),
        }
    }

    /// Newest threat reports first.
    pub fn threats(&self, limit: usize) -> Res<Vec<StoredThreat>> {
        let conn = self.read.lock().unwrap_or_else(|e| e.into_inner());
        let limit = limit as i64;
        query_rows(
            &conn,
            "SELECT id, data FROM threats ORDER BY id DESC LIMIT ?1",
            &[&limit],
            |t: &mut StoredThreat, id| t.id = id,
        )
    }

    /// Newest raw lossless EDR events first, filtered dynamically.
    pub fn edr_events(
        &self,
        limit: usize,
        event_type: Option<&str>,
        machine_id: Option<&str>,
        sysops_only: bool,
        search: Option<&str>,
    ) -> Res<Vec<StoredEdrEvent>> {
        let conn = self.read.lock().unwrap_or_else(|e| e.into_inner());
        let mut conds: Vec<String> = Vec::new();
        let mut args: Vec<SqlValue> = Vec::new();
        append_edr_event_conds(
            &mut conds,
            &mut args,
            event_type,
            machine_id,
            sysops_only,
            search,
        );
        args.push(SqlValue::Integer(limit as i64));
        let where_sql = if conds.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conds.join(" AND "))
        };
        let sql = format!(
            "SELECT id, data FROM edr_events {where_sql} ORDER BY id DESC LIMIT ?{}",
            args.len()
        );
        let mut st = conn.prepare(&sql)?;
        let rows = st.query_map(params_from_iter(args), |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, data) = row?;
            if let Some(mut item) = from_json::<StoredEdrEvent>(&data) {
                item.id = id as u64;
                out.push(item);
            }
        }
        Ok(out)
    }

    /// Streams raw lossless EDR events as NDJSON lines (chronological) over an independent
    /// read-only connection, splicing the SQLite row id without full DOM re-serialization.
    pub fn stream_export_edr_events<F>(
        &self,
        event_type: Option<&str>,
        machine_id: Option<&str>,
        search: Option<&str>,
        limit: Option<usize>,
        mut on_line: F,
    ) -> Res<u64>
    where
        F: FnMut(&[u8]) -> Result<(), ()>,
    {
        let conn = self.open_readonly()?;
        let mut conds: Vec<String> = Vec::new();
        let mut args: Vec<SqlValue> = Vec::new();
        append_edr_event_conds(&mut conds, &mut args, event_type, machine_id, false, search);
        let limit_sql = match limit.filter(|&n| n > 0) {
            Some(lim) => {
                args.push(SqlValue::Integer(lim as i64));
                format!("LIMIT ?{}", args.len())
            }
            None => String::new(),
        };
        let where_sql = if conds.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conds.join(" AND "))
        };
        let sql =
            format!("SELECT id, data FROM edr_events {where_sql} ORDER BY id ASC {limit_sql}");
        let mut st = conn.prepare(&sql)?;
        let mut rows = st.query(params_from_iter(args))?;
        let mut line_buf = Vec::with_capacity(8192);
        let mut n = 0u64;
        while let Some(r) = rows.next()? {
            let id = r.get::<_, i64>(0)? as u64;
            let data: String = r.get(1)?;
            line_buf.clear();
            let trimmed = data.trim();
            if trimmed.starts_with(r#"{"id":0,"#) && trimmed.ends_with('}') {
                let _ = write!(&mut line_buf, r#"{{"id":{id},"#);
                line_buf.extend_from_slice(&trimmed.as_bytes()[8..]);
                line_buf.push(b'\n');
            } else if let Some(mut ev) = from_json::<StoredEdrEvent>(&data) {
                ev.id = id;
                if serde_json::to_writer(&mut line_buf, &ev).is_err() {
                    continue;
                }
                line_buf.push(b'\n');
            } else {
                line_buf.extend_from_slice(trimmed.as_bytes());
                line_buf.push(b'\n');
            }
            if on_line(&line_buf).is_err() {
                return Ok(n);
            }
            n += 1;
        }
        Ok(n)
    }

    /// Exports the full lossless EDR event history as JSON lines (chronological).
    #[allow(dead_code)]
    pub fn export_edr_events(
        &self,
        event_type: Option<&str>,
        machine_id: Option<&str>,
        out: &mut Vec<u8>,
    ) -> Res<u64> {
        self.stream_export_edr_events(event_type, machine_id, None, None, |line| {
            out.extend_from_slice(line);
            Ok(())
        })
    }

    /// Newest system diagnostic reports first.
    pub fn system_reports(&self, limit: usize) -> Res<Vec<StoredSystemReport>> {
        let conn = self.read.lock().unwrap_or_else(|e| e.into_inner());
        let limit = limit as i64;
        query_rows(
            &conn,
            "SELECT id, data FROM system_reports ORDER BY id DESC LIMIT ?1",
            &[&limit],
            |r: &mut StoredSystemReport, id| r.id = id,
        )
    }
}

fn append_killchain_conds(
    conds: &mut Vec<String>,
    args: &mut Vec<SqlValue>,
    event_type: Option<&str>,
    search: Option<&str>,
    kc_alias: &str,
) {
    if let Some(et) = event_type.map(str::trim).filter(|s| !s.is_empty()) {
        let parts: Vec<&str> = et
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .take(32)
            .collect();
        if parts.len() == 1 {
            args.push(SqlValue::Text(parts[0].to_string()));
            let p = args.len();
            conds.push(format!(
                "({kc_alias}.event_type = ?{p} OR ({kc_alias}.event_type = '' AND json_extract({kc_alias}.data, '$.event') = ?{p}))"
            ));
        } else if !parts.is_empty() {
            let mut ph = Vec::with_capacity(parts.len());
            for part in parts {
                args.push(SqlValue::Text(part.to_string()));
                ph.push(format!("?{}", args.len()));
            }
            let list = ph.join(",");
            conds.push(format!(
                "({kc_alias}.event_type IN ({list}) OR ({kc_alias}.event_type = '' AND json_extract({kc_alias}.data, '$.event') IN ({list})))"
            ));
        }
    }
    if let Some(q) = search
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
    {
        args.push(SqlValue::Text(q));
        let p = args.len();
        conds.push(format!(
            "(instr({kc_alias}.search, ?{p}) > 0 OR ({kc_alias}.search = '' AND instr(lower({kc_alias}.data), ?{p}) > 0) OR instr({kc_alias}.key, ?{p}) > 0)"
        ));
    }
}

fn append_edr_event_conds(
    conds: &mut Vec<String>,
    args: &mut Vec<SqlValue>,
    event_type: Option<&str>,
    machine_id: Option<&str>,
    sysops_only: bool,
    search: Option<&str>,
) {
    if let Some(et) = event_type.map(str::trim).filter(|s| !s.is_empty()) {
        let parts: Vec<&str> = et
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .take(32)
            .collect();
        if parts.len() == 1 {
            args.push(SqlValue::Text(parts[0].to_string()));
            conds.push(format!("event_type = ?{}", args.len()));
        } else if !parts.is_empty() {
            let mut placeholders = Vec::with_capacity(parts.len());
            for p in parts {
                args.push(SqlValue::Text(p.to_string()));
                placeholders.push(format!("?{}", args.len()));
            }
            conds.push(format!("event_type IN ({})", placeholders.join(",")));
        }
    } else if sysops_only {
        conds.push("event_type GLOB 'AGENT_*'".to_string());
    }
    if let Some(m) = machine_id.map(str::trim).filter(|s| !s.is_empty()) {
        args.push(SqlValue::Text(m.to_string()));
        conds.push(format!("machine_id = ?{}", args.len()));
    }
    if let Some(q) = search
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
    {
        args.push(SqlValue::Text(q));
        conds.push(format!("instr(search, ?{}) > 0", args.len()));
    }
}

#[allow(clippy::too_many_arguments)]
fn decode_killchain_record(
    key: String,
    count: u64,
    count_all: Option<u64>,
    machines: Option<u64>,
    first_seen: String,
    last_seen: String,
    event_date: Option<String>,
    event_time: Option<String>,
    machine_override: Option<&str>,
    data: &str,
) -> Option<StoredKillchainEvent> {
    let val: serde_json::Value = serde_json::from_str(data).ok()?;
    let get_str = |k: &str| {
        val.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    Some(StoredKillchainEvent {
        key,
        count,
        count_all,
        machines,
        date: event_date.unwrap_or_else(|| get_str("date")),
        time: event_time.unwrap_or_else(|| get_str("time")),
        first_seen,
        last_seen,
        machine_id: machine_override
            .map(str::to_string)
            .unwrap_or_else(|| get_str("machine_id")),
        exe: get_str("exe"),
        event: get_str("event"),
        details: get_str("details"),
        raw: val
            .get("raw")
            .cloned()
            .unwrap_or_else(|| serde_json::Value::Object(Default::default())),
    })
}
