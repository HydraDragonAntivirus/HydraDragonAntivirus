using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace OpenEdr.Sdk
{
    /// Polling daemon: scans new/changed files with worker tasks, reports hits.
    public sealed class DaemonWatcher : IDisposable
    {
        private static readonly HashSet<string> DefaultFlag = new() { "Malicious", "Suspicious" };

        private readonly OpenEdrScanner _scanner;
        private readonly string _dir;
        private readonly int _pollMs;
        private readonly long _maxSize;
        private readonly HashSet<string> _flag;
        private readonly string _quarantineDir;
        private readonly Action<string, string> _onHit;
        private readonly int _workers;
        private readonly BlockingCollection<string> _queue = new();
        private readonly Dictionary<string, (long, long)> _seen = new();
        private readonly Dictionary<string, string> _verdictCache = new();
        private readonly object _lock = new();
        private readonly CancellationTokenSource _cts = new();
        private readonly List<Task> _tasks = new();

        public int Scanned { get; private set; }
        public int Hits { get; private set; }
        public int SkippedCache { get; private set; }

        public DaemonWatcher(OpenEdrScanner scanner, string dir, int pollMs = 2000,
            int workers = 2, long maxSizeBytes = 48L * 1024 * 1024,
            IEnumerable<string> flag = null, Action<string, string> onHit = null,
            string quarantineDir = null)
        {
            _scanner = scanner ?? throw new ArgumentNullException(nameof(scanner));
            _dir = Path.GetFullPath(dir ?? throw new ArgumentNullException(nameof(dir)));
            _pollMs = pollMs;
            _workers = Math.Max(1, workers);
            _maxSize = maxSizeBytes;
            _flag = flag != null ? new HashSet<string>(flag) : new HashSet<string>(DefaultFlag);
            _onHit = onHit;
            _quarantineDir = quarantineDir;
            if (_quarantineDir != null) Directory.CreateDirectory(_quarantineDir);
        }

        public void Start()
        {
            _tasks.Add(Task.Run(WatchLoop));
            for (int i = 0; i < _workers; i++)
                _tasks.Add(Task.Run(WorkLoop));
        }

        public void Stop()
        {
            _cts.Cancel();
            try { Task.WaitAll(_tasks.ToArray(), 5000); } catch { }
        }

        public void Dispose()
        {
            Stop();
            _queue.Dispose();
            _cts.Dispose();
        }

        private void WatchLoop()
        {
            while (!_cts.IsCancellationRequested)
            {
                try { Sweep(); } catch { }
                _cts.Token.WaitHandle.WaitOne(_pollMs);
            }
            _queue.CompleteAdding();
        }

        private void Sweep()
        {
            if (!Directory.Exists(_dir)) return;
            var qRoot = _quarantineDir != null
                ? Path.GetFullPath(_quarantineDir).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar
                : null;
            foreach (var p in Directory.EnumerateFiles(_dir, "*", SearchOption.AllDirectories))
            {
                if (_cts.IsCancellationRequested) return;
                try
                {
                    if (qRoot != null && Path.GetFullPath(p).StartsWith(qRoot, StringComparison.OrdinalIgnoreCase))
                        continue;
                    var info = new FileInfo(p);
                    if (!info.Exists || info.Length == 0 || info.Length > _maxSize) continue;
                    var key = (info.Length, info.LastWriteTimeUtc.Ticks);
                    lock (_lock)
                    {
                        if (_seen.TryGetValue(p, out var prev) && prev.Equals(key)) continue;
                        _seen[p] = key;
                    }
                    _queue.Add(p, _cts.Token);
                }
                catch { /* raced delete / cancelled */ }
            }
        }

        private void WorkLoop()
        {
            foreach (var path in _queue.GetConsumingEnumerable(_cts.Token))
            {
                try { ScanOne(path); } catch { }
                if (_cts.IsCancellationRequested) return;
            }
        }

        private void ScanOne(string path)
        {
            string digest;
            try
            {
                using var sha = SHA256.Create();
                using var fs = File.OpenRead(path);
                digest = Convert.ToHexString(sha.ComputeHash(fs));
            }
            catch { return; }

            lock (_lock)
            {
                if (_verdictCache.TryGetValue(digest, out var cached))
                {
                    SkippedCache++;
                    if (_flag.Contains(cached))
                    {
                        Hits++;
                        _onHit?.Invoke(path, cached + " (cached)");
                    }
                    return;
                }
            }

            string report;
            try { report = _scanner.ScanFile(path); }
            catch { return; }
            string verdict = ExtractVerdict(report);

            lock (_lock)
            {
                _verdictCache[digest] = verdict;
                Scanned++;
            }

            if (!_flag.Contains(verdict)) return;

            if (_quarantineDir != null)
            {
                try { File.Move(path, Path.Combine(_quarantineDir, Path.GetFileName(path)), true); }
                catch { }
            }
            lock (_lock) Hits++;
            _onHit?.Invoke(path, verdict);
        }

        private static string ExtractVerdict(string json)
        {
            if (string.IsNullOrEmpty(json)) return "Unknown";
            int i = json.IndexOf("\"verdict\"", StringComparison.Ordinal);
            if (i < 0) return "Unknown";
            int c = json.IndexOf(':', i);
            if (c < 0) return "Unknown";
            int q1 = json.IndexOf('"', c);
            if (q1 < 0) return "Unknown";
            int q2 = json.IndexOf('"', q1 + 1);
            if (q2 < 0) return "Unknown";
            return json.Substring(q1 + 1, q2 - q1 - 1);
        }
    }
}
