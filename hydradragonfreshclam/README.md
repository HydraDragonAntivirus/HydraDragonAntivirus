# hydradragonfreshclam

Developer-side tool that refreshes HydraDragon's ClamAV signature set. It is **not**
part of the portable/production build — `hydradragonav` ships with the pre-filtered
database and only reads signatures through the pure-Rust `hydradragonclamav` engine.

Two steps, run in order:

1. **Update** the official ClamAV databases (`main`, `daily`, `bytecode`) by loading
   `libfreshclam.dll` and calling its `fc_*` API (the same path the official
   `freshclam` uses).
2. **ClamJuice** the result: unpack each `.cvd`/`.cld`, keep only the Windows
   (`Win.*`) non-hash signatures (`.ndb`/`.ldb`), drop the hash databases
   (`.hdb`/`.mdb`/`.hsb`), and fold `.fp`/`.sfp` whitelists into `whitelist.db`.

The filtered `.ndb`/`.ldb` output is what gets hosted/committed and consumed by
`hydradragonclamav`.

## Usage

```powershell
# Update, then filter, deleting the source .cvd/.cld afterwards (default)
cargo run --manifest-path hydradragonfreshclam/Cargo.toml -- --db path\to\database --freshclam path\to\libfreshclam.dll

# Only download (skip filtering)
cargo run --manifest-path hydradragonfreshclam/Cargo.toml -- --no-juice

# Only re-filter databases already on disk
cargo run --manifest-path hydradragonfreshclam/Cargo.toml -- --juice-only

# Keep the original .cvd/.cld after filtering
cargo run --manifest-path hydradragonfreshclam/Cargo.toml -- --keep-source
```

Paths default to `<exe_dir>/libfreshclam.dll` and `<exe_dir>/database`, and the
certificates directory defaults to `<freshclam_dir>/certs`. All three can be
overridden via the flags above or the `FRESHCLAM_DLL_PATH`, `CLAMAV_DATABASE`,
and `CLAMAV_CERTS` environment variables.

Windows-only (depends on `libfreshclam.dll`).
