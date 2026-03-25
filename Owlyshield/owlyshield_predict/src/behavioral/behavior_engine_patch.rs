// =============================================================================
// behavior_engine.rs — PATCH: Route rootkit events through the rule engine
//
// This file documents all changes needed. Search for "PATCH:" comments to find
// each integration point in the existing code.
// =============================================================================

// ---------------------------------------------------------------------------
// PATCH 1: shared_def.rs — add four new IrpMajorOp variants
//
// In the IrpMajorOp enum, after IrpUserModeHookEvent = 20:
//
//   IrpRootkitSsdtHook      = 21,
//   IrpRootkitHiddenProcess = 22,
//   IrpRootkitHiddenDriver  = 23,
//   IrpRootkitKernelHook    = 24,
//
// In from_byte():
//   21 => IrpMajorOp::IrpRootkitSsdtHook,
//   22 => IrpMajorOp::IrpRootkitHiddenProcess,
//   23 => IrpMajorOp::IrpRootkitHiddenDriver,
//   24 => IrpMajorOp::IrpRootkitKernelHook,
//
// In is_kernel_api_event() (or equivalent helper):
//   IrpMajorOp::IrpRootkitSsdtHook
//   | IrpMajorOp::IrpRootkitHiddenProcess
//   | IrpMajorOp::IrpRootkitHiddenDriver
//   | IrpMajorOp::IrpRootkitKernelHook => true,
//
// In known_raw_event_name():
//   21 => Some("IrpRootkitSsdtHook"),
//   22 => Some("IrpRootkitHiddenProcess"),
//   23 => Some("IrpRootkitHiddenDriver"),
//   24 => Some("IrpRootkitKernelHook"),
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PATCH 2: ProcessBehaviorState — add rootkit counters
//
// In ProcessBehaviorState struct (after rootkit_implicated: bool):
//
//   /// How many SSDT hook findings were emitted for this process.
//   pub rootkit_ssdt_hook_count: u32,
//   /// How many hidden-process findings were emitted (pid == self.pid).
//   pub rootkit_hidden_process_count: u32,
//   /// How many hidden-driver findings were emitted while this process ran.
//   pub rootkit_hidden_driver_count: u32,
//   /// How many kernel inline-hook findings were emitted.
//   pub rootkit_kernel_hook_count: u32,
//   /// Total rootkit findings of any kind.
//   pub rootkit_total_count: u32,
//   /// Description of the last rootkit finding (for rule matching).
//   pub rootkit_last_description: String,
//
// In ProcessBehaviorState::new() initialise them:
//   state.rootkit_ssdt_hook_count      = 0;
//   state.rootkit_hidden_process_count = 0;
//   state.rootkit_hidden_driver_count  = 0;
//   state.rootkit_kernel_hook_count    = 0;
//   state.rootkit_total_count          = 0;
//   state.rootkit_last_description     = String::new();
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PATCH 3: record_irp_operation — handle rootkit opcodes
//
// In ProcessBehaviorState::record_irp_operation, inside the match on
// IrpMajorOp, add a new arm after IrpKernelMapSection (or alongside the
// hypervisor arm):
//
//   IrpMajorOp::IrpRootkitSsdtHook
//   | IrpMajorOp::IrpRootkitHiddenProcess
//   | IrpMajorOp::IrpRootkitHiddenDriver
//   | IrpMajorOp::IrpRootkitKernelHook => {
//       self.rootkit_total_count += 1;
//       match IrpMajorOp::from_byte(irp_op) {
//           IrpMajorOp::IrpRootkitSsdtHook      => self.rootkit_ssdt_hook_count      += 1,
//           IrpMajorOp::IrpRootkitHiddenProcess => self.rootkit_hidden_process_count += 1,
//           IrpMajorOp::IrpRootkitHiddenDriver  => self.rootkit_hidden_driver_count  += 1,
//           IrpMajorOp::IrpRootkitKernelHook    => self.rootkit_kernel_hook_count    += 1,
//           _ => {}
//       }
//       self.rootkit_last_description = msg.kernel_event_info.object_name
//           .trim_matches('\0').to_string();
//       self.rootkit_implicated = true;
//
//       // Also insert into detected_apis so api-based rule conditions fire.
//       let label = known_raw_event_name(irp_op as u32)
//           .unwrap_or("rootkit_event")
//           .to_string();
//       self.detected_apis.insert(label.clone());
//       self.all_apis_called.insert(label);
//
//       Logging::warning(&format!(
//           "[ROOTKIT EVENT] opcode={} pid={} desc=\"{}\"",
//           irp_op, msg.pid, self.rootkit_last_description
//       ));
//   },
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PATCH 4: NamedConditionGroup — add rootkit condition fields
//
// Add to NamedConditionGroup struct:
//
//   /// Minimum total rootkit findings to satisfy this condition.
//   #[serde(default)]
//   pub rootkit_total_min: Option<u32>,
//   /// Specific rootkit event types that must be present (any of).
//   /// Values: "ssdt_hook", "hidden_process", "hidden_driver", "kernel_hook"
//   #[serde(default)]
//   pub rootkit_event_types: Vec<String>,
//   /// Minimum count for a specific rootkit event type (used with rootkit_event_types).
//   #[serde(default)]
//   pub rootkit_event_min_count: Option<u32>,
//   /// Match against the description string of the last rootkit finding (substring).
//   #[serde(default)]
//   pub rootkit_description_contains: Vec<String>,
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PATCH 5: evaluate_named_condition — add rootkit evaluation
//
// In check_named_condition (or equivalent), after the hypervisor_event checks:
//
//   // --- Rootkit findings ---
//   if let Some(min) = &cond.rootkit_total_min {
//       if state.rootkit_total_count < *min {
//           return false;
//       }
//   }
//
//   if !cond.rootkit_event_types.is_empty() {
//       let min_count = cond.rootkit_event_min_count.unwrap_or(1);
//       let matched = cond.rootkit_event_types.iter().any(|t| {
//           match t.as_str() {
//               "ssdt_hook"      => state.rootkit_ssdt_hook_count      >= min_count,
//               "hidden_process" => state.rootkit_hidden_process_count >= min_count,
//               "hidden_driver"  => state.rootkit_hidden_driver_count  >= min_count,
//               "kernel_hook"    => state.rootkit_kernel_hook_count    >= min_count,
//               _                => false,
//           }
//       });
//       if !matched { return false; }
//   }
//
//   if !cond.rootkit_description_contains.is_empty() {
//       let desc = state.rootkit_last_description.to_lowercase();
//       let any_match = cond.rootkit_description_contains
//           .iter()
//           .any(|p| desc.contains(&p.to_lowercase()));
//       if !any_match { return false; }
//   }
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PATCH 6: scan_all_processes — immediate action on rootkit_implicated
//
// In scan_all_processes, inside the per-process loop, before the rule
// evaluation block (after the firewall_blocked check):
//
//   // Any rootkit finding immediately bypasses rule evaluation.
//   if state.rootkit_implicated {
//       let mut p = ProcessRecord::new(gid, app_name.clone(), exe_path_buf.clone());
//       p.is_malicious = true;
//       p.pids.insert(pid);
//       p.termination_requested = true;
//       p.notify_user_requested = true;
//       p.triggered_rule_name = Some(format!(
//           "RootkitDetection|{}|{}",
//           match (state.rootkit_ssdt_hook_count > 0,
//                  state.rootkit_hidden_process_count > 0,
//                  state.rootkit_hidden_driver_count > 0,
//                  state.rootkit_kernel_hook_count > 0) {
//               (true, _, _, _) => "SsdtHook",
//               (_, true, _, _) => "HiddenProcess",
//               (_, _, true, _) => "HiddenDriver",
//               _               => "KernelInlineHook",
//           },
//           state.rootkit_last_description
//       ));
//       Logging::warning(&format!(
//           "[ROOTKIT] Immediate action on rootkit-implicated PID {} ({}): {}",
//           pid, app_name, state.rootkit_last_description
//       ));
//       detected_processes.push(p);
//       continue;
//   }
// ---------------------------------------------------------------------------
