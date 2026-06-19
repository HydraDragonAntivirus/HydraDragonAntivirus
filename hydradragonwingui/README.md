# hydradragonwingui

A native Win32 GUI for the HydraDragon portable antivirus, written from scratch
in Rust on the `windows` crate — no GUI framework, just `CreateWindowExW`, a
window-class `wndproc` message loop, and native controls.

## What it does

- A main window with **Scan File…** and **Scan Folder…** buttons (native
  `IFileOpenDialog` shell picker, with `FOS_PICKFOLDERS` for folders).
- A read-only multiline edit control that streams detections as they are found,
  and a status line showing progress.
- Scanning runs on a **background worker thread** that drives the
  `hydradragonav` pipeline (`Pipeline::scan_file`); results are sent over an
  `mpsc` channel and the worker `PostMessageW`s a `WM_APP` ping so the UI thread
  drains them — the window never blocks while scanning.

The engine pipeline (ClamAV/YARA/ML/bloom/static) is loaded lazily on the first
scan from paths relative to the executable (`database`, `yara-x`, `bloom_filter`,
`ml/…`, `hydradragonsig_rules`), the same layout the CLI uses.

## Build / run

```powershell
cargo run --manifest-path hydradragonwingui/Cargo.toml
```

It is a GUI subsystem app (`#![windows_subsystem = "windows"]`), so it has no
console window.

## Notes

- This is the GUI front-end only; the detection logic lives in `hydradragonav`.
- Quarantine management and the remediation/disinfection flow exist in
  `hydradragonav` (CLI today) and are the natural next things to surface as GUI
  tabs/buttons.
