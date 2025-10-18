#!/usr/bin/env python3
"""
query_filters.py
Load all .cuckoo shards from ./blacklists and query domain/IP membership.

Usage:
  python query_filters.py 0--4.com
  python query_filters.py 1.2.3.4
  python query_filters.py some.sub.domain --parents
"""
import argparse
import json
import pickle
from pathlib import Path
import ipaddress
import sys

# Optional import (some installs provide library loader)
try:
    from cuckoopy import CuckooFilter  # type: ignore
except Exception:
    CuckooFilter = None  # used only as a fallback loader if available

BLACKLIST_DIR = Path("blacklists")


class MultiFilter:
    def __init__(self, dirpath: Path = BLACKLIST_DIR):
        self.dir = Path(dirpath)
        self.filters = {}  # name -> (filter_obj, prefix, meta)
        self._load_filters()

    def _load_filters(self):
        cuckoo_files = sorted(self.dir.glob("*.cuckoo"))
        for cfpath in cuckoo_files:
            name = cfpath.stem
            meta = {}
            meta_path = self.dir / f"{name}.meta.json"
            if meta_path.exists():
                try:
                    with open(meta_path, "r", encoding="utf-8") as mf:
                        meta = json.load(mf)
                except Exception:
                    meta = {}

            # Attempt to load via pickle first, then library loader
            cf = None
            load_err = None
            try:
                with open(cfpath, "rb") as fh:
                    cf = pickle.load(fh)
            except Exception as e_pickle:
                load_err = e_pickle
                if CuckooFilter is not None and hasattr(CuckooFilter, "load"):
                    try:
                        cf = CuckooFilter.load(str(cfpath))  # library-specific loader
                    except Exception as e_lib:
                        load_err = (e_pickle, e_lib)
                else:
                    # no library loader available
                    cf = None

            if cf is None:
                print(f"[WARN] Failed to load {cfpath}: {load_err}", file=sys.stderr)
                continue

            ftype = meta.get("type", meta.get("typename", "")).lower() if meta else ""
            # Normalize a few possible values to prefixes
            prefix_map = {
                "domain": "dom:",
                "dom": "dom:",
                "subdomain": "sub:",
                "sub": "sub:",
                "ipv4": "ipv4:",
                "ipv6": "ipv6:",
            }
            # If meta type absent, try to infer from filename
            if not ftype:
                n = name.lower()
                if "ipv4" in n:
                    ftype = "ipv4"
                elif "ipv6" in n:
                    ftype = "ipv6"
                elif "subdomain" in n or "subdomains" in n or "sub" in n:
                    ftype = "subdomain"
                else:
                    ftype = "domain"

            prefix = prefix_map.get(ftype, "dom:")
            self.filters[name] = (cf, prefix, meta)

    def _contains(self, cf_obj, key: str) -> bool:
        """
        Generic contains wrapper. Try common API shapes:
         - cf.contains(key)
         - key in cf_obj
         - cf_obj.lookup(key)
        """
        try:
            if hasattr(cf_obj, "contains"):
                return cf_obj.contains(key)
            if hasattr(cf_obj, "__contains__"):
                return key in cf_obj
            if hasattr(cf_obj, "lookup"):
                return cf_obj.lookup(key)
        except Exception:
            return False
        return False

    def query_domain(self, domain: str):
        domain = domain.lower().strip()
        matches = []
        for name, (cf, prefix, meta) in self.filters.items():
            key = prefix + domain
            if self._contains(cf, key):
                matches.append(name)
        return matches

    def query_with_parent_checks(self, fqdn: str):
        """
        Check fqdn and each parent domain. Returns dict:
          { matched_candidate_domain: [filter_names...] }
        Example: a.b.example.com -> checks a.b.example.com, b.example.com, example.com
        """
        fqdn = fqdn.lower().strip()
        parts = fqdn.split(".")
        res = {}
        for i in range(len(parts)):
            candidate = ".".join(parts[i:])
            matches = self.query_domain(candidate)
            if matches:
                res[candidate] = matches
        return res


def is_ip(value: str):
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def main():
    p = argparse.ArgumentParser(description="Query domain/IP against cuckoo filters in ./blacklists")
    p.add_argument("value", help="domain or IP to query (e.g. example.com or 1.2.3.4)")
    p.add_argument("--parents", action="store_true", help="for domains: check parent domains")
    args = p.parse_args()

    if not BLACKLIST_DIR.exists() or not BLACKLIST_DIR.is_dir():
        print("blacklists/ directory missing. Build filters first.", file=sys.stderr)
        sys.exit(2)

    mf = MultiFilter(BLACKLIST_DIR)
    val = args.value.strip()

    if is_ip(val):
        # Decide v4 vs v6
        v = ipaddress.ip_address(val)
        prefix = "ipv4:" if v.version == 4 else "ipv6:"
        matches = []
        for name, (cf, pfx, meta) in mf.filters.items():
            key = prefix + val
            if mf._contains(cf, key):
                matches.append(name)
        print(json.dumps({"type": "ip", "value": val, "matches": matches}, indent=2))
    else:
        if args.parents:
            res = mf.query_with_parent_checks(val)
            print(json.dumps({"type": "domain", "value": val, "matches": res}, indent=2))
        else:
            matches = mf.query_domain(val)
            print(json.dumps({"type": "domain", "value": val, "matches": matches}, indent=2))


if __name__ == "__main__":
    main()
