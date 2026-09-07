---
description: 2023 tactic - layer bisection via minimal harness with PDB-backed CPU diagnosis.
---

# Bug Diagnosis via Minimal Harness (2023 tactic)

No guessing, bisect: no edrsvc, DLL alone, disable layer by layer, measure with PDB.

> Core rule: when stuck, debug by **removing** — strip components until the
> buggy part is gone, then continue debugging from that point.

## 1. Minimal caller

`OpenEDR/owlyshield_predict/examples/minimal_firewall.rs` — calls `firewall::run()`.

```powershell
cargo build --release --example minimal_firewall
# ADMIN shell:
.\target\release\examples\minimal_firewall.exe
```

Filter is `true` — all traffic gets diverted. Ctrl-C closes the handle, traffic returns.

## 2. Layer ladder (settings only, no rebuild)

`C:\ProgramData\edrsvc\firewall_settings.json` + restart service/harness. 2-3 min traffic per step:

1. Record baseline CPU.
2. `tls_proxy.auto_start=false` → no proxy (drop = MITM side).
3. `auto_start=true` + `mitm_all_traffic=false` + `monitored_hosts=[]` → proxy idle.
4. `save_all_logs=false` → log writer off.
5. Move the `models/` dir away (no `pe_model.mpk`/`js_model.mpk` = inference skipped).

## 3. Capture (VM or local)

```cmd
wpr -start CPU -filemode
:: 30-60s in broken state
wpr -stop C:\Temp\cpu.etl
```

## 4. Resolve with PDB (dev machine)

DLL+PDB must sit side by side (`target\release`). Build profile:
`[profile.release] debug = "line-tables-only"`.

```powershell
$dbh = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbh.exe"
$sp = "<target\release dir>"; $dll = "$sp\owlyshield_ransom.dll"
& $dbh -s:$sp $dll 'x *symbol_fragment*'  # find address
& $dbh -s:$sp $dll 'laddr <hexaddress>'   # address -> file:line
```

Export-relative offsets: `base_address + offset = target`, then `laddr target`.
E.g.: `set_mitm(0x141a070)+0x4f1210 = 0x190B280` → `laddr 190B280`.

## 5. Traps (learned, don't repeat)

- System Informer `module!symbol+0x...` names on a PDB-less VM are **export-based**;
  +MB offsets like `set_mitm_enabled+0x4f...` are meaningless — resolve the real
  address with the PDB.
- Offsets are **build-specific**; resolving an old sample against a new PDB yields
  garbage (lands in fs.rs / capstone data).
- For exact names, put the PDB next to the DLL (VM included) or resolve raw
  `module+offset` lines on the dev machine.
- If a stack collapses to one frame (e.g. `ntdll!ZwWaitForAlertByThreadId`), the walk
  failed; grab 5-10 IP-line samples of the same hot TID at different times and look
  at the distribution.
- Don't confuse a cold thread (thousands of cycles) with a burner (billions).
- If `aws-lc` jitter burns CPU, use the build switch (no pin, version stays):
  `[env] AWS_LC_SYS_NO_JITTER_ENTROPY = "1"` in `owlyshield_predict/.cargo/config.toml`,
  then delete aws-lc-sys fingerprints and `cargo build --release`.
  Verify: `x *jent_read_entropy*` empty, `x *opt_out_cpu_jitter_get_seed*` present in new PDB.
- `Cargo.lock` can silently revert; verify `aws-lc-rs`/`aws-lc-sys` versions in the
  lock before building.
