"""Daemon example: watch a directory and print every Malicious/Suspicious hit.

Usage:
    python daemon_example.py [watch_dir]
"""
import os
import sys
import time

from openedr_sdk import OpenEdrScanner
from openedr_daemon import DaemonScanner


def main():
    watch = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.expanduser("~"), "Downloads")
    portable = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "..", "OpenMalwareScannerPortable"))
    scanner = OpenEdrScanner(
        dll_path=os.path.join(portable, "openedr_static.dll"),
        rules_dir=portable)

    def on_hit(hit):
        rep = hit["report"] or {}
        dets = [d.get("name") for d in rep.get("detections", [])][:3]
        print(f"[!] {hit['verdict']} {'(cached)' if hit['cached'] else ''} :: "
              f"{hit['path']} :: {dets}", flush=True)

    daemon = DaemonScanner(scanner, [watch], poll_interval=2.0,
                           workers=2, on_detection=on_hit).start()
    print(f"[*] Watching {watch} - Ctrl+C to stop", flush=True)
    try:
        while True:
            time.sleep(5)
            print(f"[...] stats={daemon.stats}", flush=True)
    except KeyboardInterrupt:
        daemon.stop()
        print(f"[*] Stopped. stats={daemon.stats}")


if __name__ == "__main__":
    main()
