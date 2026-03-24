// =============================================================================
// behavior_engine.rs — ROOTKIT DETECTION ADDITIONS
//
// Add these constants, struct, and methods to the existing behavior_engine.rs.
// Integration points are marked with "// ADD:" comments.
// =============================================================================

// ---------------------------------------------------------------------------
// ADD: to shared_def.rs (or wherever IrpMajorOp is defined)
// ---------------------------------------------------------------------------
/*
    In the IrpMajorOp enum, after IrpUsermodeHookEvent = 20:

    IrpRootkitSsdtHook      = 21,
    IrpRootkitHiddenProcess = 22,
    IrpRootkitHiddenDriver  = 23,
    IrpRootkitKernelHook    = 24,
*/

// ---------------------------------------------------------------------------
// ADD: Rootkit finding record
// ---------------------------------------------------------------------------

use std::time::{SystemTime, UNIX_EPOCH};

/// A single rootkit detection finding forwarded from the kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootkitFinding {
    pub kind: RootkitFindingKind,
    pub description: String,
    /// Memory address involved (hook target, hidden driver base, etc.)
    pub address: u64,
    /// PID for hidden-process findings, 0 otherwise.
    pub pid: u32,
    /// Auxiliary value (SSDT index, hook redirect address, …)
    pub extra: u64,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RootkitFindingKind {
    SsdtHook,
    HiddenProcess,
    HiddenDriver,
    KernelInlineHook,
    Unknown(u8),
}

impl RootkitFindingKind {
    pub fn from_irp_op(op: u8) -> Self {
        match op {
            21 => RootkitFindingKind::SsdtHook,
            22 => RootkitFindingKind::HiddenProcess,
            23 => RootkitFindingKind::HiddenDriver,
            24 => RootkitFindingKind::KernelInlineHook,
            other => RootkitFindingKind::Unknown(other),
        }
    }

    pub fn threat_label(&self) -> &'static str {
        match self {
            RootkitFindingKind::SsdtHook        => "SSDT Hook",
            RootkitFindingKind::HiddenProcess   => "Hidden Process (DKOM)",
            RootkitFindingKind::HiddenDriver    => "Hidden Driver",
            RootkitFindingKind::KernelInlineHook => "Kernel Inline Hook",
            RootkitFindingKind::Unknown(_)      => "Unknown Rootkit Event",
        }
    }

    pub fn severity(&self) -> u8 {
        // 0 = low, 1 = medium, 2 = high, 3 = critical
        match self {
            RootkitFindingKind::SsdtHook        => 3,
            RootkitFindingKind::HiddenProcess   => 3,
            RootkitFindingKind::HiddenDriver    => 3,
            RootkitFindingKind::KernelInlineHook => 2,
            RootkitFindingKind::Unknown(_)      => 1,
        }
    }
}

// ---------------------------------------------------------------------------
// ADD: to BehaviorEngine struct fields
// ---------------------------------------------------------------------------
/*
    pub rootkit_findings: Vec<RootkitFinding>,
*/

// ---------------------------------------------------------------------------
// ADD: handle_rootkit_event method on BehaviorEngine (or equivalent struct)
// ---------------------------------------------------------------------------

impl BehaviorEngine {
    /// Called from the main IRP dispatch loop when irp_op is 21–24.
    pub fn handle_rootkit_event(&mut self, msg: &IOMessage) {
        let kind = RootkitFindingKind::from_irp_op(msg.irp_op as u8);

        let description = msg
            .kernel_event_info
            .object_name
            .trim_matches('\0')
            .to_string();

        let finding = RootkitFinding {
            kind: kind.clone(),
            description: description.clone(),
            address: msg.kernel_event_info.memory_address as u64,
            pid: msg.kernel_event_info.source_pid,
            extra: msg.kernel_event_info.raw_arg1,
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };

        Logging::warning(&format!(
            "[ROOTKIT] {} — {} (addr=0x{:X} pid={} extra=0x{:X})",
            kind.threat_label(),
            description,
            finding.address,
            finding.pid,
            finding.extra,
        ));

        // Emit to findings list (used by report generation).
        self.rootkit_findings.push(finding.clone());

        // Immediately act if severity is critical.
        if kind.severity() >= 3 {
            self.on_critical_rootkit_finding(&finding);
        }
    }

    /// Respond to a critical rootkit finding.
    /// Currently: log prominently + mark the system as compromised so the
    /// next scan_all_processes pass can act on any associated process.
    fn on_critical_rootkit_finding(&mut self, finding: &RootkitFinding) {
        Logging::warning(&format!(
            "[ROOTKIT CRITICAL] {} detected: '{}' at 0x{:X}",
            finding.kind.threat_label(),
            finding.description,
            finding.address
        ));

        // If a specific PID is implicated (hidden process), mark it.
        if finding.pid != 0 {
            // Look up the GID for this PID and flag the process state.
            if let Some(state) = self.process_states.values_mut()
                .find(|s| s.pid == finding.pid)
            {
                state.rootkit_implicated = true;
                Logging::warning(&format!(
                    "[ROOTKIT] PID {} ({}) is rootkit-implicated",
                    finding.pid, state.app_name
                ));
            }
        }
    }

    /// Returns a snapshot of all rootkit findings since last clear.
    pub fn get_rootkit_findings(&self) -> &[RootkitFinding] {
        &self.rootkit_findings
    }

    /// Clears the rootkit findings list (e.g. after writing a report).
    pub fn clear_rootkit_findings(&mut self) {
        self.rootkit_findings.clear();
    }
}

// ---------------------------------------------------------------------------
// ADD: to ProcessBehaviorState struct
// ---------------------------------------------------------------------------
/*
    /// Set when RootkitDetector identifies this PID as hidden or implicated.
    pub rootkit_implicated: bool,
*/

// ---------------------------------------------------------------------------
// ADD: to scan_all_processes, inside the per-process evaluation block,
//      before the rule evaluation loop:
// ---------------------------------------------------------------------------
/*
    // Rootkit-implicated processes are immediately marked malicious.
    if state.rootkit_implicated {
        let mut p = ProcessRecord::new(gid, app_name.clone(), exe_path_buf.clone());
        p.is_malicious = true;
        p.pids.insert(pid);
        p.termination_requested = true;
        p.notify_user_requested = true;
        p.triggered_rule_name = Some("RootkitHiddenProcess".to_string());
        Logging::warning(&format!(
            "[ROOTKIT] Terminating rootkit-implicated process PID {} ({})",
            pid, app_name
        ));
        detected_processes.push(p);
        continue;
    }
*/

// ---------------------------------------------------------------------------
// ADD: to the main IRP dispatch match arm (where irp_op is matched):
// ---------------------------------------------------------------------------
/*
    IrpMajorOp::IrpRootkitSsdtHook
    | IrpMajorOp::IrpRootkitHiddenProcess
    | IrpMajorOp::IrpRootkitHiddenDriver
    | IrpMajorOp::IrpRootkitKernelHook => {
        behavior_engine.handle_rootkit_event(&msg);
    }
*/

// ---------------------------------------------------------------------------
// ADD: to report generation (WriteReportFile / WriteReportHtmlFile),
//      after existing sections:
// ---------------------------------------------------------------------------
/*
    let rootkit_findings = behavior_engine.get_rootkit_findings();
    if !rootkit_findings.is_empty() {
        report.push_str("\n=== ROOTKIT DETECTION FINDINGS ===\n");
        for f in rootkit_findings {
            report.push_str(&format!(
                "  [{}] {} — {} (addr=0x{:X})\n",
                if f.kind.severity() >= 3 { "CRITICAL" } else { "WARNING" },
                f.kind.threat_label(),
                f.description,
                f.address,
            ));
        }
    }
    behavior_engine.clear_rootkit_findings();
*/
