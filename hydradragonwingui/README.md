# hydradragonwingui

A native Win32 GUI for the HydraDragon portable antivirus, written from scratch
in Rust on the `windows` crate — no GUI framework. The entire interface is
**custom-painted** with double-buffered GDI: a branded header, a left sidebar
with hover/active navigation, flat rounded accent buttons, and a themed results
list. All chrome (header, sidebar, buttons, status bar) is drawn and hit-tested
by hand in the `wndproc`; the only real child controls are the two ListViews.

## Look & feel

- Light, modern flat theme (Segoe UI, accent blue, danger red), DPI-aware for
  crisp text on high-resolution displays.
- **Status hero banner** (Kaspersky-style) on the Scan page — a big colored badge
  + headline that reflects live state: blue "Ready to scan" / "Scanning… (N files,
  M threats)", **green** "No threats found", or **red** "N threats found". Driven
  by structured `Begin`/`Progress`/`Done` worker messages, no string parsing.
- **Gradient header** (single `GradientFill`) with a shield logo tile and a thin
  drop shadow for depth.
- Sidebar navigation with **Segoe MDL2 Assets icon glyphs** (search / lock /
  gear) and a full **accent pill** for the active page; soft hover highlight.
- Owner-painted buttons with normal / hover / pressed states; primary (accent),
  neutral (outlined) and danger (red) styles. Rounded content card.
- Results list with **zebra striping** and **severity-colored rows** (red =
  malware/phishing/abuse, amber = PUA/mining/spam/suspicious) via `NM_CUSTOMDRAW`.

All of this stays cheap: the whole window is painted into one **double-buffered**
back DC and BitBlt'd in a single pass, and a repaint only happens when hover/active
state actually changes — so the richer styling adds no perceptible cost.

## What it does

The sidebar switches between two pages:

**Scan**
- **Scan File / Scan Folder** — native `IFileOpenDialog` shell picker
  (`FOS_PICKFOLDERS` for folders).
- A report ListView (File / Verdict / Threat) that streams detections live.
- **Clean Selected** — disinfects the selected detections via the engine
  (`arenas_for_file` → `disinfect_file`): neutralize matched byte regions in
  place (keeping a `.bak`) or quarantine as fallback. Confirmed with a dialog.
- **Remove Traces** — native trace remediation (`find_traces` → `apply`) for the
  selected files: a System Restore Point + per-key `.reg` backups are made first,
  then autorun/service/task/prefetch/startup/uninstall traces are removed.
  Confirmed with a dialog.

**Quarantine**
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

## Duplicate dedup cache

Dedup is done **in the engine** (`hydradragonav::pipeline::Pipeline::scan_file_cached`),
not the GUI — the GUI only renders. To avoid re-scanning identical files, the
pipeline remembers the **MD5** of every file it classifies (files ≤ 64 MiB) in
two `fastbloom` bloom filters, persisted next to the executable:

- `good_results.bloom` — clean file hashes.
- `bad_results.bloom` — malicious file hashes.

A file whose hash is in the **good** bloom is served as clean without re-running
the engines (the common case — this is the dedup speed-up). A hash in the **bad**
bloom is **re-scanned to confirm**: the bloom is only a hint, never trusted for a
detection. The blooms are **built while scanning** (every scanned file records
into the good/bad bloom), saved after each scan and reloaded on launch, so the
scanner keeps learning across runs. An edited file (new content → new hash) is
always re-scanned.

**The first scan is faster too**, not just dedup hits: `Pipeline::scan_file`
now reads the file **exactly once** into a buffer and runs every engine (MD5
hash-bloom, ML, hydradragonsig via its single in-memory scanner, URL-bloom,
ClamAV-from-bytes, YARA) over that buffer — it used to read the file 6–7 times.
A cache miss is therefore no slower than a plain scan.

Both blooms use a light **1e-4** false-positive rate to stay small (~1.2 MB each
at the rated ~500k-file capacity; constants `CACHE_FP` / `CACHE_CAPACITY` in
`pipeline.rs`). False positives are made harmless by design: a bad-bloom false
positive just triggers one extra re-scan (a clean file is never falsely flagged),
and a good-bloom false positive only means a rare skipped re-scan.

### Settings → Clear Result Cache

The **Settings** page can wipe both blooms (on disk and in memory). This is
deliberately labelled *not recommended* — afterwards the scanner re-scans
everything from scratch and forgets every learned good/bad result. It exists for
the case where you suspect the cache is stale or corrupted.

## Icon

The HydraDragon icon (`hydradragon/assets/HydraDragonAV.ico`, shared with
`hydradragonav`) is embedded into the executable by `build.rs` (via `winres`) and
loaded into the window class — so it shows in the title bar, Alt-Tab, taskbar and
Explorer.

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
