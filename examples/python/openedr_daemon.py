"""Background daemon mode for the OpenEDR static engine (stdlib only).

Polls watch directories, scans new/changed files in worker threads and
reports hits through a callback. Slow scans never block the watcher.
"""
import hashlib
import os
import queue
import threading
import time
import shutil


class DaemonScanner:
    def __init__(self, scanner, watch_dirs, poll_interval=2.0, workers=2,
                 max_size_mb=48, flag=("Malicious", "Suspicious"),
                 on_detection=None, quarantine_dir=None):
        self.scanner = scanner
        self.watch_dirs = [os.path.abspath(d) for d in watch_dirs]
        self.poll_interval = poll_interval
        self.workers = max(1, workers)
        self.max_size = max_size_mb * 1024 * 1024
        self.flag = tuple(flag)
        self.on_detection = on_detection or (lambda hit: None)
        self.quarantine_dir = quarantine_dir
        if quarantine_dir:
            os.makedirs(quarantine_dir, exist_ok=True)
        self._queue = queue.Queue()
        self._seen = {}          # path -> (size, mtime) already queued/scanned
        self._verdict_cache = {}  # sha256 -> verdict (identical content skipped)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._threads = []
        self.stats = {"scanned": 0, "hits": 0, "errors": 0, "skipped_cache": 0}

    def start(self):
        self._stop.clear()
        t = threading.Thread(target=self._watch_loop, name="edr-watch", daemon=True)
        t.start()
        self._threads = [t]
        for i in range(self.workers):
            w = threading.Thread(target=self._work_loop, name=f"edr-scan-{i}", daemon=True)
            w.start()
            self._threads.append(w)
        return self

    def stop(self, join=True):
        self._stop.set()
        if join:
            for t in self._threads:
                t.join(timeout=5)

    def _watch_loop(self):
        while not self._stop.is_set():
            try:
                self._scan_dirs()
            except Exception:
                pass
            self._stop.wait(self.poll_interval)

    def _under_quarantine(self, dp):
        if not self.quarantine_dir:
            return False
        q = os.path.abspath(self.quarantine_dir) + os.sep
        return os.path.abspath(dp).startswith(q)

    def _scan_dirs(self):
        for root in self.watch_dirs:
            if not os.path.isdir(root):
                continue
            for dp, _, fns in os.walk(root):
                if self._under_quarantine(dp):
                    continue
                for n in fns:
                    p = os.path.join(dp, n)
                    try:
                        st = os.stat(p)
                    except OSError:
                        continue
                    if not st.st_size or st.st_size > self.max_size:
                        continue
                    key = (st.st_size, st.st_mtime_ns)
                    with self._lock:
                        if self._seen.get(p) == key:
                            continue
                        self._seen[p] = key
                    self._queue.put(p)

    def _work_loop(self):
        while not self._stop.is_set():
            try:
                path = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._scan_one(path)
            except Exception:
                with self._lock:
                    self.stats["errors"] += 1
            finally:
                self._queue.task_done()

    def _sha256(self, path, chunk=1024 * 1024):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                b = f.read(chunk)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()

    def _scan_one(self, path):
        try:
            digest = self._sha256(path)
        except OSError:
            return
        with self._lock:
            if digest in self._verdict_cache:
                self.stats["skipped_cache"] += 1
                cached = self._verdict_cache[digest]
                if cached in self.flag:
                    self.stats["hits"] += 1
                    self.on_detection({"path": path, "verdict": cached,
                                       "cached": True, "report": None})
                return
        report = self.scanner.scan_file(path)
        verdict = report.get("verdict", "Unknown")
        with self._lock:
            self._verdict_cache[digest] = verdict
            self.stats["scanned"] += 1
        if verdict in self.flag:
            if self.quarantine_dir:
                try:
                    shutil.move(path, os.path.join(
                        self.quarantine_dir, os.path.basename(path)))
                    report["_quarantined"] = True
                except OSError:
                    report["_quarantined"] = False
            with self._lock:
                self.stats["hits"] += 1
            self.on_detection({"path": path, "verdict": verdict,
                               "cached": False, "report": report})
