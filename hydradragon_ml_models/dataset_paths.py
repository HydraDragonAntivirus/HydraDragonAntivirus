"""Training folders from `dataset_paths.json`, the file multron_server_rs fills.

Same file and format as OpenEDR/multron_server_rs/src/dataset.rs, so the server, the ML
trainers and yarGen all use the same folders:

    {
      "windows_malware": "C:\\...\\usbdosyalar\\datamaliciousorder",
      "windows_clean": [
        "C:\\...\\usbdosyalar\\data2",
        { "path": "D:\\public\\some_set\\clean", "source": "public" }
      ],
      ...
    }

Every key takes a plain path ("own"), `{ "path", "source", "name" }` ("own" or "public";
the name is only for the server's statistics), or a list of those. Missing keys fall
back to the folders below. A configured folder inside another one of the same key
(`benign\\F-Droid` inside `benign`) is read once, as itself: `--sources` then picks it by
its own source. Folders whose name starts with `.` (`.cache`, `.git`, ...) are never read.

Which `dataset_paths.json` is used, first found:
  1. `--dataset-paths <file>`
  2. the HYDRADRAGON_DATASET_PATHS environment variable
  3. `dataset_paths.json` next to these scripts
  4. `dataset_paths.json` next to a locally built multron_server (target/release, debug)
`--malicious` / `--benign` on the command line (one or more folders each) override it.

Files are de-duplicated by CONTENT (SHA-256) across all folders of a platform: a file
already seen in an earlier folder of the same label is skipped, and a file that is in
BOTH labels is dropped from both (label noise; the model cannot learn it) and listed so
you can fix it. Digests are cached in `dataset_hash_cache.jsonl` next to these scripts
by path + size + modification time, so only new or changed files are hashed again (the
server's own `dataset_index.jsonl` is reused when it sits next to the
dataset_paths.json). Nothing in the dataset folders is ever moved, changed or deleted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
HASH_CACHE = os.path.join(BASE_DIR, "dataset_hash_cache.jsonl")
CONFLICTS_FILE = os.path.join(BASE_DIR, "dataset_label_conflicts.txt")

PLATFORMS = ("windows", "android", "javascript")

_BELGELER = r"C:\Users\semae\OneDrive\Belgeler"
# The real folders on the training PC (used for keys missing from dataset_paths.json).
DEFAULT_FOLDERS: Dict[str, List[str]] = {
    "windows_malware": [_BELGELER + r"\usbdosyalar\datamaliciousorder"],
    "windows_clean": [_BELGELER + r"\usbdosyalar\data2"],
    "android_malware": [_BELGELER + r"\GitHub\HydraDragonAV-Mobile\dataset\malware"],
    "android_clean": [_BELGELER + r"\GitHub\HydraDragonAV-Mobile\dataset\benign"],
    "javascript_malware": [_BELGELER + r"\usbdosyalar\javascript\datamaliciousorder"],
    "javascript_clean": [_BELGELER + r"\usbdosyalar\javascript\data2"],
}


# --------------------------------------------------------------------------- config

def find_config(explicit: Optional[str] = None) -> Optional[str]:
    """Path of the dataset_paths.json to use, or None."""
    if explicit:
        if not os.path.isfile(explicit):
            raise SystemExit(f"--dataset-paths: {explicit} not found")
        return explicit
    env = os.environ.get("HYDRADRAGON_DATASET_PATHS", "").strip()
    if env:
        if not os.path.isfile(env):
            raise SystemExit(f"HYDRADRAGON_DATASET_PATHS: {env} not found")
        return env
    server = os.path.join(REPO_ROOT, "OpenEDR", "multron_server_rs", "target")
    for p in (
        os.path.join(BASE_DIR, "dataset_paths.json"),
        os.path.join(server, "release", "dataset_paths.json"),
        os.path.join(server, "debug", "dataset_paths.json"),
    ):
        if os.path.isfile(p):
            return p
    return None


def parse_folder_list(value) -> List[Tuple[str, str]]:
    """One key of dataset_paths.json -> [(folder, "own" | "public")], as dataset.rs reads it."""
    if value is None:
        return []
    items = value if isinstance(value, list) else [value]
    out: List[Tuple[str, str]] = []
    for item in items:
        if isinstance(item, str):
            path, source = item, "own"
        elif isinstance(item, dict) and isinstance(item.get("path"), str):
            path, source = item["path"], str(item.get("source") or "own").lower()
            if source not in ("own", "public"):
                raise SystemExit(f"dataset_paths.json: unknown source {source!r} for {path} (own or public)")
        else:
            raise SystemExit(f"dataset_paths.json: cannot read folder entry {item!r}")
        if path.strip() and all(os.path.normcase(path) != os.path.normcase(p) for p, _ in out):
            out.append((path, source))
    return out


def load_config(path: Optional[str]) -> Dict[str, List[Tuple[str, str]]]:
    """Every key of dataset_paths.json (missing keys: the default folders)."""
    raw = {}
    if path:
        with open(path, encoding="utf-8-sig") as fh:
            raw = json.load(fh)
        if not isinstance(raw, dict):
            raise SystemExit(f"{path}: expected a JSON object")
    out = {}
    for key, folders in DEFAULT_FOLDERS.items():
        out[key] = parse_folder_list(raw[key]) if key in raw else [(f, "own") for f in folders]
    return out


# --------------------------------------------------------------------------- argparse

def add_common_args(parser: argparse.ArgumentParser):
    """--dataset-paths, --sources, --no-dedupe (for trainers that read several platforms)."""
    g = parser.add_argument_group("dataset folders (default: dataset_paths.json, see dataset_paths.py)")
    g.add_argument("--dataset-paths", default=None, help="dataset_paths.json to read (default: searched, see dataset_paths.py)")
    g.add_argument("--sources", choices=("all", "own", "public"), default="all",
                   help="Only folders of this source from dataset_paths.json (default: all)")
    g.add_argument("--no-dedupe", action="store_true",
                   help="Do not hash files (no duplicate or label-conflict removal; faster first run)")
    return g


def add_args(parser: argparse.ArgumentParser, platform: str) -> None:
    """add_common_args plus --malicious / --benign (one or more folders each)."""
    assert platform in PLATFORMS
    g = add_common_args(parser)
    g.add_argument("--malicious", nargs="+", action="extend", default=None, metavar="DIR",
                   help=f"Malicious folder(s); overrides {platform}_malware in dataset_paths.json")
    g.add_argument("--benign", nargs="+", action="extend", default=None, metavar="DIR",
                   help=f"Benign folder(s); overrides {platform}_clean in dataset_paths.json")


def _key(path: str) -> str:
    return os.path.normcase(os.path.abspath(path)).rstrip("\\/")


def configured(args, platform: str) -> Tuple[List[str], List[str]]:
    """Every folder of the platform that is read on its own: the --malicious / --benign
    folders when given, else every folder of dataset_paths.json (any source)."""
    cfg = load_config(find_config(getattr(args, "dataset_paths", None)))
    mal = getattr(args, "malicious", None) or [p for p, _ in cfg[f"{platform}_malware"]]
    ben = getattr(args, "benign", None) or [p for p, _ in cfg[f"{platform}_clean"]]
    return list(mal), list(ben)


def resolve(args, platform: str) -> Tuple[List[str], List[str]]:
    """(malicious folders, benign folders) for a platform, printed."""
    cfg_path = find_config(getattr(args, "dataset_paths", None))
    cfg = load_config(cfg_path)
    sources = getattr(args, "sources", "all")

    def pick(key: str, override: Optional[List[str]]) -> List[str]:
        if override:
            return list(dict.fromkeys(override))
        return [p for p, s in cfg[key] if sources == "all" or s == sources]

    mal = pick(f"{platform}_malware", getattr(args, "malicious", None))
    ben = pick(f"{platform}_clean", getattr(args, "benign", None))
    print(f"[*] Dataset folders ({platform}) from {cfg_path or 'built-in defaults'}:", flush=True)
    for label, dirs in (("malicious", mal), ("benign", ben)):
        for d in dirs:
            print(f"      {label:<9} {d}{'' if os.path.isdir(d) else '   (MISSING)'}", flush=True)
    return mal, ben


# --------------------------------------------------------------------------- files

def walk(folder: str, skip_hidden: bool = True, skip_dirs: Iterable[str] = ()) -> Iterator[str]:
    """Every file under `folder` (sorted, so the order is the same on every run).
    Folders starting with `.` and the `skip_dirs` (configured folders nested in this
    one, read on their own) are not entered."""
    skip = {_key(d) for d in skip_dirs} - {_key(folder)}
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs
                   if not (skip_hidden and d.startswith(".")) and _key(os.path.join(root, d)) not in skip]
        dirs.sort()
        for f in sorted(files):
            yield os.path.join(root, f)


class HashCache:
    """SHA-256 by path + size + mtime (whole seconds, like the server's cache)."""

    def __init__(self, extra_index: Optional[str] = None):
        self.map: Dict[str, Tuple[int, int, str]] = {}
        self.new: List[dict] = []
        for p in (extra_index, HASH_CACHE):
            if p and os.path.isfile(p):
                with open(p, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        try:
                            c = json.loads(line)
                            self.map[c["p"]] = (int(c["s"]), int(c["m"]), str(c["h"]).lower())
                        except (ValueError, KeyError, TypeError):
                            continue
        self.hashed = 0

    def sha256(self, path: str) -> Optional[str]:
        try:
            st = os.stat(path)
        except OSError:
            return None
        size, mtime = st.st_size, int(st.st_mtime)
        hit = self.map.get(path)
        if hit and hit[0] == size and hit[1] == mtime:
            return hit[2]
        h = hashlib.sha256()
        try:
            with open(path, "rb") as fh:
                for block in iter(lambda: fh.read(1 << 20), b""):
                    h.update(block)
        except OSError:
            return None
        digest = h.hexdigest()
        self.map[path] = (size, mtime, digest)
        self.new.append({"p": path, "s": size, "m": mtime, "h": digest})
        self.hashed += 1
        if len(self.new) >= 5000:
            self.flush()
        return digest

    def flush(self) -> None:
        if not self.new:
            return
        with open(HASH_CACHE, "a", encoding="utf-8") as fh:
            for c in self.new:
                fh.write(json.dumps(c, ensure_ascii=False) + "\n")
        self.new = []


def _take(folders: Iterable[str], keep: Callable[[str], bool], max_files: int,
          cache: Optional[HashCache], skip_hidden: bool,
          nested: Iterable[str] = ()) -> Tuple[List[Tuple[str, Optional[str]]], int]:
    """[(path, sha256 or None)] in folder order, duplicates by content skipped."""
    out: List[Tuple[str, Optional[str]]] = []
    seen_hash, seen_path = set(), set()
    dups = 0
    for folder in folders:
        if not os.path.isdir(folder):
            continue
        for path in walk(folder, skip_hidden, nested):
            if max_files and len(out) >= max_files:
                return out, dups
            key = os.path.normcase(os.path.abspath(path))
            if key in seen_path or not keep(path):
                continue
            seen_path.add(key)
            sha = None
            if cache is not None:
                sha = cache.sha256(path)
                if sha is None:
                    continue
                if sha in seen_hash:
                    dups += 1
                    continue
                seen_hash.add(sha)
            out.append((path, sha))
    return out, dups


def collect(args, platform: str, keep: Optional[Callable[[str], bool]] = None, max_per_class: int = 0,
            skip_hidden: bool = True) -> Tuple[List[str], List[str]]:
    """(malicious files, benign files) of a platform: every configured folder, in order,
    content duplicates and files present under both labels removed."""
    mal_dirs, ben_dirs = resolve(args, platform)
    all_mal, all_ben = configured(args, platform)
    keep = keep or (lambda _p: True)
    cache = None
    if not getattr(args, "no_dedupe", False):
        cfg_path = find_config(getattr(args, "dataset_paths", None))
        server_index = os.path.join(os.path.dirname(cfg_path), "dataset_index.jsonl") if cfg_path else None
        cache = HashCache(server_index)
        print("[*] Hashing files for duplicate / label-conflict removal (cached; --no-dedupe skips it)...", flush=True)
    try:
        mal, mal_dups = _take(mal_dirs, keep, max_per_class, cache, skip_hidden, all_mal)
        ben, ben_dups = _take(ben_dirs, keep, max_per_class, cache, skip_hidden, all_ben)
    finally:
        if cache is not None:
            cache.flush()
    conflicts = 0
    if cache is not None:
        both = {h for _, h in mal} & {h for _, h in ben}
        if both:
            conflicts = len(both)
            with open(CONFLICTS_FILE, "w", encoding="utf-8") as fh:
                fh.write("# Same content under both labels; left out of training. Fix the label in the dataset.\n")
                for label, rows in (("malicious", mal), ("benign", ben)):
                    for p, h in rows:
                        if h in both:
                            fh.write(f"{h}\t{label}\t{p}\n")
            mal = [r for r in mal if r[1] not in both]
            ben = [r for r in ben if r[1] not in both]
        print(f"[*] Hashed {cache.hashed} new/changed files; skipped {mal_dups} malicious and {ben_dups} benign "
              f"duplicates; {conflicts} files in both labels left out"
              + (f" (listed in {CONFLICTS_FILE})" if conflicts else ""), flush=True)
    print(f"[+] {platform}: {len(mal)} malicious, {len(ben)} benign files", flush=True)
    return [p for p, _ in mal], [p for p, _ in ben]


# --------------------------------------------------------------------------- feature chunks

class ChunkManifest:
    """`chunk_manifest.json` in a chunk folder: which file list every chunk was built
    from. A chunk is reused only when it was built from exactly the same files, and only
    the chunks of the last extraction are loaded (stale ones from an older, longer file
    list are ignored). Chunk folders without a manifest (older runs) are loaded as before."""

    NAME = "chunk_manifest.json"

    def __init__(self, chunk_dir: str):
        self.path = os.path.join(chunk_dir, self.NAME)
        self.entries: Dict[str, str] = {}
        if os.path.isfile(self.path):
            with open(self.path, encoding="utf-8") as fh:
                self.entries = json.load(fh)

    @staticmethod
    def digest(files: List[str]) -> str:
        return hashlib.sha256("\n".join(files).encode("utf-8", "surrogatepass")).hexdigest()

    def is_current(self, chunk_path: str, files: List[str]) -> bool:
        name = os.path.basename(chunk_path)
        return os.path.isfile(chunk_path) and self.entries.get(name) == self.digest(files)

    def record(self, chunk_path: str, files: List[str]) -> None:
        self.entries[os.path.basename(chunk_path)] = self.digest(files)
        self.save()

    def keep_only(self, prefix: str, names: List[str]) -> None:
        """Forget every `prefix*` chunk not in `names` (the current extraction)."""
        names_set = set(names)
        self.entries = {k: v for k, v in self.entries.items() if not k.startswith(prefix) or k in names_set}
        self.save()

    def save(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.entries, fh, indent=1, sort_keys=True)
        os.replace(tmp, self.path)

    def chunk_files(self, chunk_dir: str, pattern_prefix: str, legacy: List[str]) -> List[str]:
        """Chunks to load: the manifest's (when there is one), else every legacy match."""
        if not os.path.isfile(self.path):
            return sorted(legacy)
        return sorted(os.path.join(chunk_dir, n) for n in self.entries
                      if n.startswith(pattern_prefix) and os.path.isfile(os.path.join(chunk_dir, n)))
