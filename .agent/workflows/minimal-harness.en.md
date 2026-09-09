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
- For steered SYNs with no accept, `netstat -ano | findstr 8877`: a
  `SYN_RECEIVED` pileup means the SYN-ACK can't get back. Cause was rewriting
  SRC to 127.0.0.1 in the steer (no socket bound there) — rewrite DST ONLY,
  the return leg is fixed via the NAT table.
- Root-cause chain (Sep 2026, 2 weeks): ① `emerging-all.yaml` (50k rules) ran
  per packet (`metadata_only` ignored) → crawling DNS + CPU. ② Steer rewrote
  SRC to 127.0.0.1 → SYN-ACK to an unbound socket → SYN_RECEIVED pileup.
  ③ After DST-only + LAN-redirect the SYN-ACK reached the client naked
  (`LAN:8877` instead of expected `internet:443`) → client RST, handshake never
  completed. Fix: un-rewrite src of EVERY packet from the listen port with a
  NAT entry (no loopback condition). Proof: pktmon SYN-ACK+RST sequence +
  `steer/accept stats` counter (steers present, parsed 0).
- `Cargo.lock` can silently revert; verify `aws-lc-rs`/`aws-lc-sys` versions in the
  lock before building.
- Kernel block list was write-only: zero callers of `IsPathBlocked`, plus a
  DOS/NT form mismatch. Fix: canonicalize with `OwlyNormalizePathForMatch` at
  ADD, enforce in filemon preCreate (trusted bypass preserved). Needs driver
  build + reboot.
- Sep-2026 case: the `metadata_only` modifier on `!include emerging-all.yaml` in
  `rules.yaml` was ignored by the parser → 50,422 ET rules evaluated per packet,
  workers starved and the kernel queue overflowed (`allowed` yet dead traffic +
  crawling DNS). Fix: the `sdk.rs` include parser honors the modifier (skips its
  rules, still merges `monitored_sites`).
