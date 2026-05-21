# Zillya AVEngine `.dat` Signature Files

The `bin\aveng` directory contains more than DLL and EXE files. It also contains the engine's detection databases. SDK code passes this directory to the engine through two `TCoreInit_Interface` fields:

- `EPath`: directory that contains antivirus engine DLL/EXE files.
- `VPath`: directory that contains virus database and signature files.

In this package, both fields normally point to the same `aveng` directory. `CoreMain.DLL` loads the `.dat` files in its own closed binary format during initialization.

## Format

These files are not text-based YARA rules, ClamAV `.ndb` files, or hand-editable signature lists. A quick look at the first bytes shows the binary database markers:

- `vs000005.dat`: `5A 49 4C 32`, ASCII `ZIL2`
- `vl005.dat`: `5A 49 4C 31`, ASCII `ZIL1`
- `wlist.dat`: `5A 49 4C 33`, ASCII `ZIL3`
- `release.dat`: plain-text release timestamp, `2020.02.25 14:31` in this package
- `vs000001.dat`: `DELETED`

Treat the `.dat` files as closed Zillya engine database blocks. Do not edit, rename, or selectively mix them.

## File Groups

- `vsNNNNNN.dat`: main malware signature database blocks. Large files hold the primary signature set; higher-numbered smaller files appear to be supplemental or incremental database pieces.
- `vlNNN.dat`: auxiliary database files, likely used for virus names, family labels, or detection metadata.
- `wlist.dat` and `wf001.dat`: based on naming and location, these should be treated as whitelist or trusted-object helper data.
- `nexcl.dat`: small binary helper data, likely for exclusions or special rules.
- `fr001.dat`, `pa001.dat`, `vpedia_*.dat`: additional resource, package, or localized virus encyclopedia/metadata files.
- `release.dat` and `avbd.ver`: small metadata files that carry database release or version information.

## Operational Notes

- Ship the `.dat` set as a consistent whole. Missing or mismatched pieces can reduce detection quality or cause `CoreInit` failures.
- For updates, replace the full database set from a trusted source instead of editing individual files.
- Check `license.rtf` before redistribution; the engine binaries and database files may have redistribution restrictions.
- To use a different signature directory, pass that directory through `VPath` in the `CoreInit` call.
