# hydradragonwingui

A native Win32 GUI for the HydraDragon portable antivirus, written from scratch
in Rust on the `windows` crate — no GUI framework, just `CreateWindowExW`, a
window-class `wndproc` message loop, and native controls (a tab control, two
report-mode ListViews, push buttons, a status line).

## What it does

A **tab control** switches between two pages:

**Scan tab**
- **Scan File…** / **Scan Folder…** — native `IFileOpenDialog` shell picker
  (`FOS_PICKFOLDERS` for folders).
- A report **ListView** (File / Verdict / Threat) that streams detections as
  they are found, plus a live status line.
- **Clean Selected** — disinfects the selected detections via the engine
  (`arenas_for_file` → `disinfect_file`): neutralize matched byte regions in
  place (keeping a `.bak`) or quarantine as fallback. Confirmed with a dialog.
- **Remove Traces** — runs native trace remediation (`find_traces` → `apply`)
  for the selected files: a System Restore Point + per-key `.reg` backups are
  made first, then autorun/service/task/prefetch/startup/uninstall traces are
  removed. Confirmed with a dialog.

**Quarantine tab**
- **Refresh / Restore Selected / Delete Selected** — drives
  `hydradragonav::quarantine::Quarantine` (list / restore / delete) over the
  XOR-encoded quarantine store (`<exe>/quarantine`).

## Threading

Scanning, cleaning and trace-removal run on a **background worker thread** that
owns the `hydradragonav` pipeline (loaded lazily on first use). UI↔worker talk
over `mpsc` channels; the worker `PostMessageW`s a `WM_APP` ping so the UI thread
drains results and updates the ListView without ever blocking. Quarantine
list/restore/delete are fast file ops and run on the UI thread.

The engine pipeline (ClamAV/YARA/ML/bloom/static) is loaded from paths relative
to the executable (`database`, `yara-x`, `bloom_filter`, `ml/…`,
`hydradragonsig_rules`), the same layout the CLI uses.

## Build / run

```powershell
cargo run --manifest-path hydradragonwingui/Cargo.toml
```

It is a GUI subsystem app (`#![windows_subsystem = "windows"]`), so it has no
console window.

## Notes

- This is the GUI front-end only; all detection/disinfection/remediation logic
  lives in `hydradragonav`.
- Clean and Remove-Traces act on system state and need Administrator for
  HKLM/services/tasks/prefetch operations.
- Uses the `windows` 0.62 crate (independent of `hydradragonav`'s 0.58 — the two
  never share Win32 types across the Rust API boundary).
