# Multron server API

The multron server (`multron_server.exe`) has two HTTP servers:

| | Address | Who uses it |
|---|---|---|
| **Dashboard API** | `127.0.0.1:9440` (`--ui`) | The dashboard page, Multron Updater, analyst scripts on this computer. **Never expose it through the tunnel.** |
| **Scan server** | `127.0.0.1:5306` (settings: host / port / path), published through the Cloudflare tunnel | Clients (Multron Win Cleaner, …) over the WebSocket, and the viruskov.com website (`/api/v1/*`). |

Every endpoint is listed in the [reference](#reference) below, generated from the route tables in `src/dashboard.rs` and `src/scan_server.rs` (handler doc comments and request structs).

## Dashboard API: access rules

- **Only from this computer.** The connection must come from a loopback address (127.0.0.1 / ::1) *and* the `Host` header must name this computer (`localhost`, `127.0.0.1`, `[::1]`, with or without a port); a missing `Host` header is refused too. Anything else gets `403 dashboard is only available on this computer`. The server refuses to start with a non-loopback `--ui` address.
- **Analyst keys.** When `analyst_keys.txt` next to `multron_server.exe` has keys (one `<key> <analyst name>` per line, keys of 16+ characters, `#` comments), the calls that write human verdicts or change what decides a verdict — `/api/review`, `/api/review/start`, `/api/review/release`, `/api/review/delete`, `/api/reviews/bulk`, `/api/reviews/requeue`, `/api/signatures`, `/api/signatures/delete`, `/api/fp/ignore`, `/api/fp/unignore`, `/api/companies`, `/api/rules`, `/api/bans/add`, `/api/bans/remove` — need `X-Multron-Analyst-Key: <key>` (else `401`). The analyst name stored with a verdict is then the key's owner; an `analyst` field in the body is ignored. Without the file (or with no keys) these calls stay open, as before. The dashboard has an "Analyst key" field in Human analysis (kept in that browser profile only); `GET /api/analyst/whoami` says whether keys are on and whose key was sent. Keep the file readable only by the Windows account that runs the server.
- **POST needs `X-Multron-Dashboard: 1`.** Every state-changing call (all `POST`s) must send this header, otherwise `403 forbidden`. `GET`s need nothing. This keeps a web page in a browser from changing the server.
- **Archive server (read-only mode):** on the archive copy only `GET`s and a few calls (`/api/start`, `/api/stop`, `/api/maintenance`, `/api/limits`, the alyzer viewer, retrohunt on the archive, …) are allowed; the rest answer `403` with `{"ok": false, "error": "archive server: read-only …"}`.
- **Bodies are JSON** (`Content-Type: application/json`). Answers are JSON: `{"ok": true, …}` on success, `{"error": "…"}` (sometimes with `"ok": false`) and a 4xx/5xx status on failure.
- Field names are as written in the tables (`snake_case`), except where a table shows otherwise.

```powershell
# GET: nothing special
Invoke-RestMethod "http://127.0.0.1:9440/api/reviews?limit=100"

# POST: JSON body + the dashboard header
Invoke-RestMethod -Method Post "http://127.0.0.1:9440/api/review" `
  -Headers @{ "X-Multron-Dashboard" = "1" } -ContentType "application/json" `
  -Body '{"sha256":"<sha256>","verdict":"clean","analyst":"emirhan"}'
```

```python
import requests
BASE = "http://127.0.0.1:9440"
H = {"X-Multron-Dashboard": "1"}
H["X-Multron-Analyst-Key"] = "<your key from analyst_keys.txt>"   # when keys are on
requests.post(f"{BASE}/api/review", headers=H, json={"sha256": sha, "verdict": "clean"})
```

## Reviews: paging and filters

`GET /api/reviews` returns the human analysis queue.

- **No parameters:** the oldest 5000 pending files, as the dashboard always got them. `all=1`: every pending file (no limit).
- **Paging:** `offset` and `limit` (default 5000). Pending files are ordered oldest first (`requested_at`); filters apply first, then the page is cut.
- **Filters** (all optional, combined with AND; every list is comma separated, case-insensitive):

| Parameter | Meaning | Example |
|---|---|---|
| `ext` | Only these extensions (no dot; `-` = files without one) | `ext=exe,dll,-` |
| `not_ext` | Leave these extensions out | `not_ext=js,css,png` |
| `engine_verdict` | Only these current engine verdicts: `malicious`, `suspicious`, `unknown`, `clean`, `possible_clean` | `engine_verdict=unknown,suspicious` |
| `folder` | Only files whose name or a seen folder / full path contains this text | `folder=\downloads\` |
| `not_folder` | Leave out files whose name or a folder contains any of these | `not_folder=found.000,\temp\,wp-content,diskraptor` |
| `recent` | `0` leaves the 200 most recent verdicts out of the answer (by default they come on the first page only) | `recent=0` |

Answer:

```jsonc
{
  "ok": true,
  "stats": { "pending": 34012, "in_progress": 2, "completed": 5120, ... },   // whole queue, not the page
  "coverage": { ... },
  "matched": 29105,        // pending files that pass the filters
  "offset": 0,
  "returned": 1000,        // items in this page
  "next_offset": 1000,     // null on the last page
  "pending": [             // this page, oldest first
    {
      "sha256": "…", "status": "pending", "stage": "…", "requested_at": "…",
      "engine_verdict": "unknown", "verdict": null, "virustotal": "https://…",
      "ext": "exe",
      "file_names": ["setup.exe"], "file_size": 123456,
      "folders": ["%USERPROFILE%\\Downloads"], "full_folders": ["C:\\Users\\…\\Downloads"],
      "seen_count": 3, "sightings": [...],
      "current_verdict": "unknown", "current_threat": null,
      "detections": [...], "signer": {...},
      "engine_detail": "…",          // last engine detail from the verdict cache, if any
      "classification": {...}
    }
  ],
  "recent": [ ... ]        // 200 most recent verdicts (first page only by default)
}
```

Walking the whole queue, leaving the parked groups out:

```python
import requests
BASE = "http://127.0.0.1:9440"
params = {"not_folder": r"found.000,\temp\,wp-content,diskraptor", "limit": 1000, "offset": 0, "recent": 0}
while True:
    page = requests.get(f"{BASE}/api/reviews", params=params).json()
    for item in page["pending"]:
        ...  # analyse item
    if page["next_offset"] is None:
        break
    params["offset"] = page["next_offset"]
```

The queue changes while you walk it (new files are added at the end, verdicts remove files), so a verdict saved while paging can shift later pages by a few items. Walking with the same filters until `next_offset` is `null`, and then once more from `offset=0`, picks up anything that moved.

Saving a verdict for one file: `POST /api/review` (`sha256`, `verdict` = malicious | suspicious | clean, `threat_name` for malicious, `note`, `internal_note`, `analyst`). Many at once: `POST /api/reviews/bulk` (`sha256s`, at most 100 000 per request, one `verdict`, `dry_run` to count first).

## Scan WebSocket protocol

`GET /ws` (the path in the settings) upgrades to a WebSocket. All messages are JSON text frames; file bytes go as binary frames only after the server asks for them.

1. **Hello** (within 10 s): `{"type":"hello","version":3,"client":"MultronWinCleaner/1.2","token":"…"}`. Version 2 and 3 are accepted. A wrong token, a bad version or an engine that is still loading closes the session with `{"type":"error","message":"…"}`.
   The server answers `{"type":"hello_ok","version":3,"engine":"…","pipeline":N,"checkBatch":N,"maxMB":N,"encodings":["br"],"updating":false}`.
2. **Hash check** (version 3): `{"type":"check","items":[{"id":1,"sha256":"…","name":"a.exe","size":1234,"folder":"%USERPROFILE%\\Downloads","path":"C:\\Users\\…\\Downloads","rescan":false}, …]}` (at most `checkBatch` items). For each item the server sends either a **result** (verdict already known), nothing yet (another client is uploading the same file; the result follows), or `{"type":"need_upload","id":1}`.
3. **Scan / upload:** `{"type":"scan","id":1,"sha256":"…","name":"a.exe","size":1234}` (optionally `"encoding":"br","csize":<compressed bytes>` for a Brotli upload). The server answers `{"type":"send_file","id":1}`, the client sends the file bytes as binary frames, and the server sends the **result** when the scan is done. Too large, over the hourly upload limit or during maintenance: `{"type":"error","id":1,"message":"…"}`.
4. **URL scan:** `{"type":"scan_url","id":7,"url":"https://…"}` → `{"type":"url_result","id":7,"result":{…ECS…}}`.

A **result** is an Elastic Common Schema (8.11+) document: `{"type":"result","id":1,"@timestamp":"…","ecs":{…},"event":{…},"file":{…},"antivirus":{…},"threat":{…},"rule":{…}}`. Flooding (too many messages or hash checks per second), unknown message types, invalid JSON or binary data without `send_file` close the session and count against the client's IP.

## Scan server HTTP API (`/api/v1`)

Public, CORS `*`, behind the IP ban / rate-limit guard. On the archive server only `GET`s work. Details are in the reference below.

## Reference

Generated by `tools/gen_api_doc.py` from the code; edit the handler doc comments, not this part.

### Dashboard API (127.0.0.1:9440)

#### `GET /`

The dashboard page (HTML).

<sub>Handler: `src/dashboard.rs` → `handle_index`</sub>

#### `GET /api/state`

Everything the dashboard header shows: engine status, listener, settings, connected clients, all-time telemetry counts, kept-file counts, queue and memory figures, and the event log since `since` (sequence number).

Query parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| `since` | `integer` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_state`</sub>

#### `GET /api/scan-queue`

Files being scanned right now and files waiting for the engine, oldest first (500 each; `all=1`: all).

Query parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| `all` | `string` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_scan_queue`</sub>

#### `POST /api/alyzer/open`

Opens a file and returns its token, the static report, the engine/human verdict we already have, and the signer seen at the last scan.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `sha256` | `string` | no | SHA-256 of a file kept in multron_incoming. |
| `path` | `string` | no | Or a path on this server (the dashboard only answers on localhost). |

<sub>Handler: `src/alyzer.rs` → `handle_open`</sub>

#### `GET /api/alyzer/list`

Currently open files (for the page's "recent" list).

<sub>Handler: `src/alyzer.rs` → `handle_list`</sub>

#### `GET /api/alyzer/bytes`

Raw bytes [offset, offset+len) of an open file (len capped at 1 MB).

Query parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| `token` | `string` | yes |  |
| `offset` | `integer` | no |  |
| `len` | `integer` | no |  |

<sub>Handler: `src/alyzer.rs` → `handle_bytes`</sub>

#### `GET /api/alyzer/search`

Searches the open file for a byte pattern (`pattern`, hex), forward from `from` or backward with `back=true`. Returns the offset of the match.

Query parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| `token` | `string` | yes |  |
| `pattern` | `string` | yes | Hex bytes to find, e.g. "4d5a90" (the page turns ASCII / UTF-16 text into hex). |
| `from` | `integer` | no |  |
| `back` | `boolean` | no | true: search backwards from `from` (exclusive). |

<sub>Handler: `src/alyzer.rs` → `handle_search`</sub>

#### `GET /api/alyzer/strings`

Every ASCII and UTF-16LE string (with its file offset), like the Strings page of the Pascal VirusKovAlyzer. At most 50,000 entries.

Query parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| `token` | `string` | yes |  |
| `min` | `integer` | no |  |
| `q` | `string` | no | Case-insensitive filter. |

<sub>Handler: `src/alyzer.rs` → `handle_strings`</sub>

#### `GET /api/alyzer/disasm`

Disassembly of an open file: layout (format, architecture, entry, sections) and up to `count` instructions from the chosen place.

Query parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| `token` | `string` | yes |  |
| `arch` | `string` | no | "auto" (from the file header) or x86, x64, arm, thumb, arm64. |
| `at` | `string` | no | Where to start: empty / "entry", a virtual address in hex ("401000" or "0x401000"), or a file offset as "o:400" / "o:0x400". |
| `count` | `integer` | no |  |

<sub>Handler: `src/alyzer.rs` → `handle_disasm`</sub>

#### `GET /api/alyzer/archive`

Archive contents (hydradragonextractor, as the engine uses it) and the archive heuristics (encrypted bait, RLO names, ...).

Query parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| `token` | `string` | yes |  |

<sub>Handler: `src/alyzer.rs` → `handle_archive`</sub>

#### `POST /api/alyzer/archive/open`

Extracts one archive entry and opens it as a new document.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `token` | `string` | yes |  |
| `name` | `string` | yes |  |

<sub>Handler: `src/alyzer.rs` → `handle_archive_open`</sub>

#### `GET /api/alyzer/decompile`

hydradragondecompiler (decompiler-lite): strings the code references by address, strings built on the stack and characteristic opcode patterns (API hashing, PEB walks, indirect syscalls).

Query parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| `token` | `string` | yes |  |
| `min` | `integer` | no |  |
| `all` | `boolean` | no | Also include plain ASCII / UTF-16 runs (the Strings tab has those already). |

<sub>Handler: `src/alyzer.rs` → `handle_decompile`</sub>

#### `POST /api/alyzer/unpack`

Unicorn PE emulation (hydradragonunicorn, the engine's own unpacker): runs the file in the emulator, dumps the memory image and opens it as a new document.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `token` | `string` | yes |  |

<sub>Handler: `src/alyzer.rs` → `handle_unpack`</sub>

#### `POST /api/alyzer/scan`

Scans the open file with the engine now (nothing is kept, the verdict cache and telemetry are not touched) and returns verdict, threat, engines and signer.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `token` | `string` | yes |  |

<sub>Handler: `src/alyzer.rs` → `handle_scan`</sub>

#### `POST /api/alyzer/save`

Writes a patched COPY to `alyzer_edited/` next to the server (never the original) and returns its path and SHA-256.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `token` | `string` | yes |  |
| `patches` | `array of (u64, String)` | yes | [offset, "hex bytes"] pairs from the hex editor. |
| `open` | `boolean` | no | Open the saved copy right away (returns its report like /open). |

<sub>Handler: `src/alyzer.rs` → `handle_save`</sub>

#### `GET /api/events/ecs`

Dashboard events since sequence number `since`, as ECS JSON. Returns `{events, seq}`.

Query parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| `since` | `integer` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_events_ecs`</sub>

#### `POST /api/start`

Starts the scan listener (WebSocket + public API) with these settings and saves them.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `host` | `string` | yes |  |
| `port` | `integer` | yes |  |
| `path` | `string` | yes |  |
| `autostart` | `boolean` | no |  |
| `keep_threats` | `boolean` | no |  |
| `keep_clean` | `boolean` | no | Keep clean PE / APK files (own quota, `--keep-clean-gb`). |
| `keep_possible_clean` | `boolean` | no | Keep `possible_clean` files (TLSH smart whitelist) in the work folder. |
| `keep_all_unique` | `boolean` | no | Keep every unique file (SHA-256 not kept yet), in every category (default on). |
| `collect_xorfilter` | `boolean` | no | Collect XOR-filter (benign whitelist / malicious hash) hits for checking (default on). |
| `offload_target` | `string` | no | Folder kept files are moved to (empty = off) and whether that happens automatically when space runs low. |
| `offload_auto` | `boolean` | no |  |
| `maintenance` | `boolean` | no | Normal maintenance mode stays on across restarts (the "updating" mode set by Multron Updater is never saved). |
| `archive` | `boolean` | no | Archive server (same as `--archive`): set once in the archive folder's multron_server.json, so the server always starts read-only there. |
| `archive_mirror` | `string` | no | Folder the archive mirror copies everything to (empty = off). |
| `rescan_after_reload` | `boolean` | no | Rescan kept unknown / possible_clean files after every engine reload. |
| `lzma_low_disk` | `boolean` | no | Low-disk LZMA2 compression of kept files (dashboard). A new key on purpose: the old `compress_low_disk` was written as true by every earlier build without being a choice, so it is ignored and the default is off. |
| `low_disk_gb` | `integer` | no |  |
| `limits` | `crate::limits::LimitSettings` | no | Limits edited in the dashboard; None until they are changed there once. |

<sub>Handler: `src/dashboard.rs` → `handle_start`</sub>

#### `POST /api/stop`

Stops the scan listener.

<sub>Handler: `src/dashboard.rs` → `handle_stop`</sub>

#### `GET /api/maintenance`

Maintenance state: `{maintenance, mode, message, activeWork, pid, handoff, seamlessUpdate}`. `activeWork` = files being uploaded or scanned (the updater waits for 0).

<sub>Handler: `src/dashboard.rs` → `handle_maintenance_status`</sub>

#### `POST /api/maintenance`

Maintenance mode: the listener stays up (health answers) but new file and URL scans are refused with a message while in-flight work finishes. "maintenance" is the normal mode (kept across restarts); "updating" is set by Multron Updater right before it closes and replaces the server, so the updated server starts with scans open again.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `enabled` | `boolean` | no |  |
| `mode` | `string` | no | "maintenance" (default) or "updating" (Multron Updater, before it replaces the exe). |

<sub>Handler: `src/dashboard.rs` → `handle_maintenance`</sub>

#### `POST /api/handoff/begin`

Seamless update: the new version started next to this one and loads its engine. Scans go on ("getting updated"); called again every few seconds as a heartbeat.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `pid` | `integer` | no |  |
| `drain_seconds` | `integer` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_handoff_begin`</sub>

#### `POST /api/handoff/cancel`

Seamless update abandoned by the new version (it could not load).

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `pid` | `integer` | no |  |
| `drain_seconds` | `integer` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_handoff_cancel`</sub>

#### `POST /api/handoff/release`

Seamless update, last step: refuse new scans for a moment, let the ones in progress finish, close the sessions, let the writers flush, answer and exit, so the new version can bind the ports.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `pid` | `integer` | no |  |
| `drain_seconds` | `integer` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_handoff_release`</sub>

#### `POST /api/keep-possible-clean`

Whether `possible_clean` files (TLSH smart whitelist) are kept in the work folder. Applies at once and is saved to multron_server.json.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `enabled` | `boolean` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_keep_possible_clean`</sub>

#### `POST /api/keep-clean`

Whether clean PE/APK files are kept in multron_incoming. Saved to multron_server.json.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `enabled` | `boolean` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_keep_clean`</sub>

#### `POST /api/keep-all-unique`

Keep every unique file (any category, any type; quotas still apply).

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `enabled` | `boolean` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_keep_all_unique`</sub>

#### `POST /api/collect-xorfilter`

Collect XOR-filter hash hits (benign whitelist / malicious hash filter) for checking.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `enabled` | `boolean` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_collect_xorfilter`</sub>

#### `GET /api/dataset/conflicts`

ML dataset label conflicts (same content already in the other label folder in a file the server did not write), newest first.

<sub>Handler: `src/dashboard.rs` → `handle_dataset_conflicts`</sub>

#### `POST /api/dataset/remove-incoming-duplicates`

ML dataset copies of files in multron_incoming (server-written `<SHA256>.<ext>`): `dry_run` counts them, otherwise they are moved to the backup folders. multron_incoming stays. Copies of samples with an analyst verdict (clean / malicious) always stay: they are the human labels the models train on.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `dry_run` | `boolean` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_remove_incoming_duplicates`</sub>

#### `POST /api/kept/sort-by-type`

Sorts multron_incoming by ClamAV file type: `<category>/<type>/`.

<sub>Handler: `src/dashboard.rs` → `handle_sort_kept_by_type`</sub>

#### `POST /api/kept/unpack-xz`

Unpacks every `.xz` file in multron_incoming and deletes the `.xz` once the unpacked SHA-256 is verified.

<sub>Handler: `src/dashboard.rs` → `handle_unpack_kept_xz`</sub>

#### `POST /api/compress-low-disk`

Whether kept files are stored LZMA2-compressed (`.xz`) when disk space runs low. Saved.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `enabled` | `boolean` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_compress_low_disk`</sub>

#### `POST /api/rescan`

Rescans one file kept in multron_incoming with the current engine, analyst signatures and smart whitelist; updates cache, telemetry and the website.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `sha256` | `string` | yes |  |

<sub>Handler: `src/dashboard.rs` → `handle_rescan_one`</sub>

#### `GET /api/rescan/bulk`

Progress of the bulk rescan.

<sub>Handler: `src/dashboard.rs` → `handle_rescan_status`</sub>

#### `POST /api/rescan/bulk`

Rescans every kept file of the given categories (empty = all) with the current engine. Returns `{queued}`; 409 when one is already running.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `categories` | `array of string` | no | "unknown", "possible_clean", "suspicious", "malicious", "clean" ("threat" = both); empty = unknown + possible_clean for a rescan, every category for a move. |

<sub>Handler: `src/dashboard.rs` → `handle_rescan_bulk`</sub>

#### `POST /api/rescan/stop`

Stops the bulk rescan.

<sub>Handler: `src/dashboard.rs` → `handle_rescan_stop`</sub>

#### `GET /api/rescan/audit`

Duplicate / not-listed kept files per category. Walks the work folder.

<sub>Handler: `src/dashboard.rs` → `handle_rescan_audit`</sub>

#### `POST /api/rescan/audit`

Rescans the problem files found by `GET /api/rescan/audit` (duplicates and/or files missing from telemetry).

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `categories` | `array of string` | no |  |
| `kinds` | `array of string` | no | "duplicate", "not_listed" (empty = both). |

<sub>Handler: `src/dashboard.rs` → `handle_rescan_audit_bulk`</sub>

#### `GET /api/rescan/log`

Every rescanned file (newest first, across runs) with old/new verdict and engines.

<sub>Handler: `src/dashboard.rs` → `handle_rescan_log`</sub>

#### `GET /api/kept/info/:sha256`

Where a kept upload is on this server (multron_incoming/<category>/...).

Path parameter: the `:` segment of the URL.

<sub>Handler: `src/dashboard.rs` → `handle_kept_info`</sub>

#### `POST /api/reviews/requeue`

Queues again the files with this engine verdict that have no human review ("missing" in the coverage line), plus the removed ones when asked.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `verdict` | `string` | yes |  |
| `include_removed` | `boolean` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_reviews_requeue`</sub>

#### `POST /api/kept/reveal`

Opens Explorer on this server with the kept file selected. The dashboard only answers on localhost, so this is the machine the analyst is sitting at (or the remote desktop of the VDS).

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `sha256` | `string` | yes |  |

<sub>Handler: `src/dashboard.rs` → `handle_kept_reveal`</sub>

#### `POST /api/kept/dedupe`

Removes extra copies of the same sample from this server's work folder.

<sub>Handler: `src/dashboard.rs` → `handle_kept_dedupe`</sub>

#### `POST /api/rescan/after-reload`

Whether every kept file is rescanned automatically after an engine reload. Saved.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `enabled` | `boolean` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_rescan_after_reload`</sub>

#### `POST /api/mirror/config`

Sets the backup archive mirror folder (absolute path, e.g. `\\\\ARCHIVEPC\\viruskov_archive`; empty = off) and starts a mirror run.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `target` | `string` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_mirror_config`</sub>

#### `POST /api/mirror/run`

Runs the archive mirror now.

<sub>Handler: `src/dashboard.rs` → `handle_mirror_run`</sub>

#### `POST /api/mirror/stop`

Stops the running mirror.

<sub>Handler: `src/dashboard.rs` → `handle_mirror_stop`</sub>

#### `POST /api/mirror/dedupe`

Removes duplicate samples from the archive mirror. Returns `{removed, bytes}`.

<sub>Handler: `src/dashboard.rs` → `handle_mirror_dedupe`</sub>

#### `POST /api/offload/config`

Sets the folder kept files are moved to (another disk / network share) and whether moving is automatic.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `target` | `string` | no |  |
| `auto` | `boolean` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_offload_config`</sub>

#### `POST /api/offload/start`

Moves the kept files of the given categories to the move target now. Returns `{files}`.

<sub>Handler: `src/dashboard.rs` → `handle_offload_start`</sub>

#### `POST /api/offload/stop`

Stops moving files.

<sub>Handler: `src/dashboard.rs` → `handle_offload_stop`</sub>

#### `POST /api/limits`

Saves new limits from the dashboard. They apply at once and survive a restart.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `max_mb` | `integer` | yes |  |
| `max_inflight_mb` | `integer` | yes |  |
| `max_conns` | `integer` | yes |  |
| `max_per_ip` | `integer` | yes |  |
| `pipeline` | `integer` | yes |  |
| `max_check_batch` | `integer` | yes |  |
| `connects_per_min` | `integer` | yes |  |
| `upload_mb_per_hour` | `integer` | yes |  |
| `msgs_per_sec` | `integer` | yes |  |
| `checks_per_sec` | `integer` | yes |  |
| `ban_strikes` | `integer` | yes |  |
| `ban_minutes` | `integer` | yes |  |

<sub>Handler: `src/dashboard.rs` → `handle_limits`</sub>

#### `POST /api/limits/reset`

Back to the command-line values; the saved limits are removed.

<sub>Handler: `src/dashboard.rs` → `handle_limits_reset`</sub>

#### `POST /api/unban`

Lifts every automatic (rate-limit) IP ban. Returns `{unbanned}`.

<sub>Handler: `src/dashboard.rs` → `handle_unban`</sub>

#### `GET /api/insights/stats`

Telemetry totals by verdict and the file-type statistics.

<sub>Handler: `src/dashboard.rs` → `handle_dashboard_insights_stats`</sub>

#### `GET /api/insights/:sha256`

Everything known about one SHA-256: telemetry insight, prevalence, human review and a VirusTotal link (`found: false` when never seen).

Path parameter: the `:` segment of the URL.

<sub>Handler: `src/dashboard.rs` → `handle_dashboard_insights_hash`</sub>

#### `POST /api/rules`

General runtime rule reload without restart or rebuild.  POST /api/rules?kind=url|strings|registry|yara_src with the raw rule text as the body (64 MB cap). Replaces the live rule set of that kind; binary bundles (ML models, compiled .yrc) stay restart-only.

Query parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| `kind` | `string` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_rules_reload`</sub>

#### `POST /api/engine/reload`

Hot reload of the whole engine in this process; the listener and sessions stay up.

Query parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| `keep_cache` | `boolean` | no | Keep cached verdicts (default: invalidate them so files are rescanned). |

<sub>Handler: `src/dashboard.rs` → `handle_engine_reload`</sub>

#### `GET /api/reviews`

The human analysis queue. Without parameters: the oldest 5000 pending files (`all=1`: every one). With `offset` / `limit` and the filters (`ext`, `not_ext`, `engine_verdict`, `folder`, `not_folder`): the pending files that pass the filters, oldest first, one page at a time; `next_offset` is null on the last page.

Query parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| `all` | `string` | no |  |
| `offset` | `integer` | no | Skip this many (after filtering), oldest first. |
| `limit` | `integer` | no | Page size (default 5000; `all=1` = no limit). |
| `ext` | `string` | no | Extensions, comma separated, lower case without the dot ("exe,dll"; "-" = none). |
| `not_ext` | `string` | no | Extensions to leave out, comma separated. |
| `engine_verdict` | `string` | no | Current engine verdicts, comma separated (malicious, suspicious, unknown, clean, possible_clean). |
| `folder` | `string` | no | Only files whose name or a folder contains this text (case-insensitive). |
| `not_folder` | `string` | no | Leave out files whose name or a folder contains any of these (comma separated, case-insensitive): "found.000,\\temp\\,wp-content". |
| `recent` | `string` | no | Include the 200 most recent verdicts ("0" leaves them out; default on the first page only). |

<sub>Handler: `src/dashboard.rs` → `handle_reviews_list`</sub>

#### `POST /api/review`

Saves an analyst verdict for one file. The kept file moves to the verdict's folder, the TLSH analyst list is updated and the file is copied into the ML dataset under the verdict's label.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `sha256` | `string` | yes |  |
| `verdict` | `string` | yes |  |
| `threat_name` | `string` | no |  |
| `note` | `string` | no |  |
| `internal_note` | `string` | no |  |
| `analyst` | `string` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_review_save`</sub>

#### `POST /api/review/delete`

Deletes the human review of one file (and its TLSH analyst entry). 404 when there is none.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `sha256` | `string` | yes |  |

<sub>Handler: `src/dashboard.rs` → `handle_review_delete`</sub>

#### `POST /api/review/start`

"Start analysis" (Valkyrie-style start date): marks the hash as being analysed.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `sha256` | `string` | yes |  |
| `analyst` | `string` | no |  |
| `take_over` | `boolean` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_review_start`</sub>

#### `POST /api/review/release`

Releases a file an analyst had started (`/api/review/start`) back to the queue.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `sha256` | `string` | yes |  |

<sub>Handler: `src/dashboard.rs` → `handle_review_release`</sub>

#### `GET /api/reviews/similar/:sha256`

Up to 5 similar files (TLSH) with their verdicts.

Path parameter: the `:` segment of the URL.

<sub>Handler: `src/dashboard.rs` → `handle_review_similar`</sub>

#### `GET /api/fs/list`

Lists a folder on the server's own disk (for the folder whitelist picker).

Query parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| `path` | `string` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_fs_list`</sub>

#### `POST /api/folder-wl/types`

Counts the file types in a folder before a folder whitelist (multron_incoming and the move target are never walked).

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `path` | `string` | yes |  |
| `exts` | `array of string` | no |  |
| `max_mb` | `integer` | no | Skip files larger than this (0 = no limit). |

<sub>Handler: `src/dashboard.rs` → `handle_folder_types`</sub>

#### `POST /api/folder-wl/start`

Starts hashing a folder on the server's disk for a bulk whitelist (`exts` filters, `max_mb` skips large files).

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `path` | `string` | yes |  |
| `exts` | `array of string` | no |  |
| `max_mb` | `integer` | no | Skip files larger than this (0 = no limit). |

<sub>Handler: `src/dashboard.rs` → `handle_folder_start`</sub>

#### `GET /api/folder-wl/status`

Progress of the folder hashing job.

<sub>Handler: `src/dashboard.rs` → `handle_folder_status`</sub>

#### `POST /api/folder-wl/stop`

Stops the folder hashing job.

<sub>Handler: `src/dashboard.rs` → `handle_folder_stop`</sub>

#### `POST /api/reviews/bulk`

One verdict for many files at once: the given hashes, or the last finished folder hashing (`folder_job`). `verdict` = malicious | suspicious | clean | dismiss (dismiss = remove pending entries). A malicious verdict needs `threat_name`. `dry_run` only reports what would change.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `sha256s` | `array of string` | no |  |
| `folder_job` | `boolean` | no | Use the hashes of the last finished server-side folder hashing (`folder_wl`). |
| `verdict` | `string` | yes | malicious \| suspicious \| clean, or "dismiss" (remove pending entries from the queue). |
| `threat_name` | `string` | no |  |
| `note` | `string` | no |  |
| `internal_note` | `string` | no |  |
| `analyst` | `string` | no |  |
| `dry_run` | `boolean` | no |  |
| `override_conflicts` | `boolean` | no | Also write hashes that conflict (engine flagged them, or an analyst gave another verdict). |
| `only_seen` | `boolean` | no | Skip hashes VirusKov has never seen (a folder whitelist may hold many of them). |

<sub>Handler: `src/dashboard.rs` → `handle_reviews_bulk`</sub>

#### `GET /api/signatures`

The analyst signatures (Signature room): kind, name, source, modified, plus the naming categories and platforms.

<sub>Handler: `src/dashboard.rs` → `handle_signatures_list`</sub>

#### `POST /api/signatures`

Validates the name and the source for its engine, then writes `analyst_signatures/<engine>/<Name>.<ext>`. YARA is compiled into the live engine (append-only); ClamAV and HydraDragonSig sets are rebuilt from disk at once.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `kind` | `string` | no |  |
| `name` | `string` | yes |  |
| `source` | `string` | yes |  |

<sub>Handler: `src/dashboard.rs` → `handle_signature_save`</sub>

#### `POST /api/signatures/delete`

Deletes an analyst signature. ClamAV / HydraDragonSig ones are unloaded at once; YARA stays loaded until the next engine reload.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `kind` | `string` | no |  |
| `name` | `string` | yes |  |

<sub>Handler: `src/dashboard.rs` → `handle_signature_delete`</sub>

#### `GET /api/fp/detections/:sha256`

Signatures named in the last result for this file (verdict cache, else the rescan log), with the engine each belongs to.

Path parameter: the `:` segment of the URL.

<sub>Handler: `src/dashboard.rs` → `handle_fp_detections`</sub>

#### `GET /api/fp/lists`

The false-positive ignore lists (ClamAV `.ign2`, HydraDragonSig, YARA) with their entries.

<sub>Handler: `src/dashboard.rs` → `handle_fp_lists`</sub>

#### `POST /api/fp/ignore`

Adds a signature to a false-positive ignore list (`kind` = clamav | hydrasig | yara) with reason, analyst and the file it was seen on.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `kind` | `string` | yes |  |
| `name` | `string` | yes |  |
| `file` | `string` | no |  |
| `reason` | `string` | no |  |
| `analyst` | `string` | no |  |
| `sha256` | `string` | no |  |
| `file_name` | `string` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_fp_ignore`</sub>

#### `POST /api/fp/unignore`

Removes a signature from a false-positive ignore list. Active after the next engine reload.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `kind` | `string` | yes |  |
| `file` | `string` | yes |  |
| `name` | `string` | yes |  |

<sub>Handler: `src/dashboard.rs` → `handle_fp_unignore`</sub>

#### `GET /api/sources`

Client IPs that sent files, with file / path counts (bot and abuse hunting).

Query parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| `ip` | `string` | no |  |
| `path` | `string` | no |  |
| `limit` | `integer` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_sources`</sub>

#### `GET /api/sources/files`

Files one client IP sent, with the full paths it sent them from.

Query parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| `ip` | `string` | no |  |
| `path` | `string` | no |  |
| `limit` | `integer` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_source_files`</sub>

#### `GET /api/bans`

Analyst IP bans plus the automatic (rate limit) bans active now.

<sub>Handler: `src/dashboard.rs` → `handle_bans_list`</sub>

#### `POST /api/bans/add`

Bans an IP or CIDR range on every public route and closes its open sessions.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `ip` | `string` | yes |  |
| `reason` | `string` | no |  |
| `analyst` | `string` | no |  |
| `minutes` | `integer` | no | 0 = until removed. |

<sub>Handler: `src/dashboard.rs` → `handle_ban_add`</sub>

#### `POST /api/bans/remove`

Removes an analyst IP ban.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `ip` | `string` | yes |  |
| `reason` | `string` | no |  |
| `analyst` | `string` | no |  |
| `minutes` | `integer` | no | 0 = until removed. |

<sub>Handler: `src/dashboard.rs` → `handle_ban_remove`</sub>

#### `GET /api/retrohunt`

Progress and hits of the running / last retrohunts.

<sub>Handler: `src/dashboard.rs` → `handle_retrohunt_status`</sub>

#### `POST /api/retrohunt/stop`

Stops every running retrohunt.

<sub>Handler: `src/dashboard.rs` → `handle_retrohunt_stop`</sub>

#### `POST /api/retrohunt/archive`

Archive server: matches a rule (saved or only in the editor) against every file of the mirrored work folder. Match only: no engine, nothing written.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `kind` | `string` | no |  |
| `name` | `string` | yes |  |
| `source` | `string` | yes |  |

<sub>Handler: `src/dashboard.rs` → `handle_retrohunt_archive`</sub>

#### `GET /api/naming`

Normalizes a threat name to the naming scheme. Returns `{name, yara_id}` or `{ok:false, error}`.

Query parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| `name` | `string` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_naming_check`</sub>

#### `GET /api/companies`

(No doc comment on the handler yet.)

<sub>Handler: `src/dashboard.rs` → `handle_companies_get`</sub>

#### `POST /api/companies`

Replaces the company allow / block lists (a name may not be in both). Active at once; cached verdicts are cleared.

JSON body:

| Name | Type | Required | Description |
|---|---|---|---|
| `allow` | `array of string` | no |  |
| `block` | `array of string` | no |  |

<sub>Handler: `src/dashboard.rs` → `handle_companies_save`</sub>

#### `GET /api/analyst/whoami`

The company (signer) allow and block lists. Who the dashboard is talking to: `enforced` = `analyst_keys.txt` has keys (verdicts then need `X-Multron-Analyst-Key`), `analyst` = owner of the key sent, if valid.

<sub>Handler: `src/dashboard.rs` → `handle_analyst_whoami`</sub>


### Scan server (port 5306, public through the tunnel)

#### `GET /ws`

The scan WebSocket used by Multron Win Cleaner and the other clients (hello, check, scan, scan_url; see API.md).

<sub>Handler: `src/scan_server.rs` → `ws_handler`</sub>

#### `GET /health`

Liveness: `{status: ok | maintenance, maintenance, maintenanceMode, ...}`.

<sub>Handler: `src/scan_server.rs` → `handle_health`</sub>

#### `GET /api/v1/insights/:sha256`

Public telemetry for one SHA-256 (verdict, prevalence, first/last seen). No folders, names of users or IPs.

Path parameter: the `:` segment of the URL.

<sub>Handler: `src/scan_server.rs` → `handle_hash_insights`</sub>

#### `GET /api/v1/insights/stats`

Public telemetry totals for the website statistics page.

<sub>Handler: `src/scan_server.rs` → `handle_insights_stats`</sub>

#### `GET /api/v1/dataset/stats`

Public ML dataset totals (own / public / user-submitted) for the statistics page.

<sub>Handler: `src/scan_server.rs` → `handle_dataset_stats`</sub>

#### `GET /api/v1/reviews`

Public list of the latest analyst verdicts plus queue statistics (for the website).

<sub>Handler: `src/scan_server.rs` → `handle_public_reviews`</sub>

#### `GET /api/v1/report/:sha256`

Full file page data: VirusKovAlyzer static report + telemetry + human analysis.

Path parameter: the `:` segment of the URL.

<sub>Handler: `src/scan_server.rs` → `handle_file_report`</sub>

#### `GET /api/v1/similar/:sha256`

Public list of files similar to this SHA-256 (TLSH) with their verdicts.

Path parameter: the `:` segment of the URL.

<sub>Handler: `src/scan_server.rs` → `handle_similar`</sub>

#### `GET /api/v1/feed/daily`

MalwareBazaar-style daily list: hashes first seen on a UTC day with a malicious or suspicious verdict. `?date=YYYY-MM-DD` (default today), `&format=json|csv|txt`, `&all=1` to include clean and unknown files too.

<sub>Handler: `src/scan_server.rs` → `handle_daily_feed`</sub>

#### `GET /api/v1/sample/:sha256`

Sample download for researchers: only malicious/suspicious files, only with a valid `X-API-Key`, delivered as a ZIP encrypted with the password `infected`.

Path parameter: the `:` segment of the URL.

<sub>Handler: `src/scan_server.rs` → `handle_sample_download`</sub>

#### `POST /api/v1/disinfect`

Signature-based disinfection + cloud restoration (see `disinfect.rs`). Body: the infected file. `X-File-Path` (or `?path=`): where it is on the client, used to tell Windows system files apart. Disinfection is only the recommended action for system files; the repaired bytes are returned with `?download=repaired`.

Query parameters:

| Name | Type | Required | Description |
|---|---|---|---|
| `download` | `string` | no | `repaired`: answer with the repaired file instead of the JSON report; `generic`: the generic repair (never recommended). |
| `path` | `string` | no | Client path of the file (same as the `X-File-Path` header). |

<sub>Handler: `src/scan_server.rs` → `handle_disinfect`</sub>

#### `GET /api/v1/restore/:sha256`

Clean copy for cloud restoration: only files known clean (analyst-verified clean or in the verified benign corpus) and kept on this server, raw bytes.

Path parameter: the `:` segment of the URL.

<sub>Handler: `src/scan_server.rs` → `handle_restore_download`</sub>

#### `POST /api/v1/reviews/request/:sha256`

A visitor asks for human analysis of a hash. Only hashes already seen in telemetry are accepted (so the queue cannot be filled with random hashes); rate limited per IP.

Path parameter: the `:` segment of the URL.

<sub>Handler: `src/scan_server.rs` → `handle_review_request`</sub>

#### `POST /api/v1/scan/url`

Scans a URL (JSON body, `url`) and returns the ECS result.

<sub>Handler: `src/scan_server.rs` → `handle_scan_url`</sub>

#### `GET /api/v1/scan/url`

Same as POST, with `?url=`.

<sub>Handler: `src/scan_server.rs` → `handle_scan_url_get`</sub>
