using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace VirusKov.ReactOS
{
    /// <summary>
    /// Real-time protection without a kernel driver: the folders where malware usually
    /// lands (Desktop, Downloads, Startup, Temp and any extra folders) are watched with
    /// FileSystemWatcher; every new or changed executable is hashed and checked in the
    /// cloud. FileSystemWatcher does not exist on Windows 9x and can lose events on
    /// ReactOS, so the folders are also polled (every 2 minutes, or every 30 seconds when
    /// the watcher is not available). It detects and quarantines; it cannot stop a file
    /// from starting (that needs a driver).
    /// </summary>
    public sealed class RealtimeMonitor : IDisposable
    {
        private readonly Settings settings;
        private readonly List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();
        private readonly Dictionary<string, DateTime> pending = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> known = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); // path -> "size|mtime"
        private readonly Dictionary<string, ScanResult> verdictCache = new Dictionary<string, ScanResult>(StringComparer.OrdinalIgnoreCase); // sha -> result
        private readonly object sync = new object();
        private Thread worker;
        private volatile bool running;
        private bool watcherMode;

        /// <summary>A threat was found (already quarantined when <c>quarantined</c> is true).</summary>
        public event Action<ScanResult, bool> ThreatFound;

        public RealtimeMonitor(Settings settings)
        {
            this.settings = settings;
        }

        public bool Running
        {
            get { return running; }
        }

        public string Mode
        {
            get { return !running ? "off" : watcherMode ? "file watcher + polling every 2 min" : "polling every 30 s (no file watcher on this system)"; }
        }

        public List<string> Folders()
        {
            var l = new List<string>();
            Add(l, Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
            Add(l, Environment.GetFolderPath(Environment.SpecialFolder.Startup));
            string profile = Platform.Env("USERPROFILE");
            if (profile != null) Add(l, Path.Combine(profile, "Downloads"));
            Add(l, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Personal), "Downloads"));
            string allUsers = Platform.Env("ALLUSERSPROFILE");
            if (allUsers != null) Add(l, Path.Combine(allUsers, "Start Menu\\Programs\\Startup"));
            Add(l, Path.GetTempPath());
            foreach (string f in settings.ExtraFolderList()) Add(l, f);
            return l;
        }

        private static void Add(List<string> l, string dir)
        {
            if (string.IsNullOrEmpty(dir)) return;
            dir = dir.TrimEnd('\\');
            if (!Directory.Exists(dir)) return;
            foreach (string x in l)
                if (x.Equals(dir, StringComparison.OrdinalIgnoreCase)) return;
            l.Add(dir);
        }

        public void Start()
        {
            if (running) return;
            running = true;
            watcherMode = false;
            foreach (string dir in Folders())
            {
                try
                {
                    var w = new FileSystemWatcher(dir);
                    w.IncludeSubdirectories = true;
                    w.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size;
                    w.InternalBufferSize = 64 * 1024;
                    w.Created += OnChanged;
                    w.Changed += OnChanged;
                    w.Renamed += (s, e) => Queue(e.FullPath);
                    w.Error += (s, e) => Log.Write("real-time: watcher error, polling covers it: " + e.GetException().Message);
                    w.EnableRaisingEvents = true;
                    watchers.Add(w);
                    watcherMode = true;
                }
                catch (Exception e)
                {
                    // Windows 9x: PlatformNotSupportedException. Polling still covers the folder.
                    Log.Write("real-time: no file watcher for " + dir + " (" + e.GetType().Name + "), polling it");
                }
            }
            // First pass only learns what is already there (the on-demand scan covers it).
            Poll(true);
            worker = new Thread(Loop);
            worker.IsBackground = true;
            worker.Name = "VirusKov real-time";
            worker.Start();
            Log.Write("real-time protection on: " + Mode);
        }

        public void Stop()
        {
            running = false;
            foreach (FileSystemWatcher w in watchers)
            {
                try { w.EnableRaisingEvents = false; w.Dispose(); } catch (Exception) { }
            }
            watchers.Clear();
            Log.Write("real-time protection off");
        }

        private void OnChanged(object sender, FileSystemEventArgs e)
        {
            Queue(e.FullPath);
        }

        private void Queue(string path)
        {
            lock (sync) pending[path] = DateTime.UtcNow;
        }

        private void Loop()
        {
            DateTime nextPoll = DateTime.UtcNow.AddSeconds(watcherMode ? 120 : 30);
            while (running)
            {
                Thread.Sleep(1000);
                try
                {
                    if (DateTime.UtcNow >= nextPoll)
                    {
                        Poll(false);
                        nextPoll = DateTime.UtcNow.AddSeconds(watcherMode ? 120 : 30);
                    }
                    ProcessPending();
                }
                catch (Exception e)
                {
                    Log.Write("real-time: " + e.Message);
                }
            }
        }

        /// <summary>Finds new or changed files the watcher may have missed.</summary>
        private void Poll(bool learnOnly)
        {
            foreach (string dir in Folders())
                PollDir(dir, 0, learnOnly);
        }

        private void PollDir(string dir, int depth, bool learnOnly)
        {
            if (!running || depth > 3) return;
            try
            {
                foreach (string f in Directory.GetFiles(dir))
                {
                    var fi = new FileInfo(f);
                    string stamp = fi.Length + "|" + fi.LastWriteTimeUtc.Ticks;
                    string old;
                    bool changed;
                    lock (sync)
                    {
                        changed = !known.TryGetValue(f, out old) || old != stamp;
                        known[f] = stamp;
                    }
                    if (changed && !learnOnly) Queue(f);
                }
                foreach (string d in Directory.GetDirectories(dir))
                    PollDir(d, depth + 1, learnOnly);
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        /// <summary>Files untouched for 3 seconds (downloads finished) are checked.</summary>
        private void ProcessPending()
        {
            var ready = new List<string>();
            lock (sync)
            {
                foreach (KeyValuePair<string, DateTime> p in pending)
                    if ((DateTime.UtcNow - p.Value).TotalSeconds >= 3) ready.Add(p.Key);
                foreach (string r in ready) pending.Remove(r);
            }
            if (ready.Count == 0) return;

            var jobs = new List<FileJob>();
            foreach (string path in ready)
            {
                if (!File.Exists(path) || path.StartsWith(AppPaths.ProgramDir, StringComparison.OrdinalIgnoreCase)) continue;
                if (!FileFilter.IsExecutable(path)) continue;
                FileJob j = Scanner.MakeJob(path);
                if (j == null || j.Size == 0) { if (j == null) Queue(path); continue; } // locked: try again later
                ScanResult cached;
                lock (sync)
                {
                    if (verdictCache.TryGetValue(j.Sha256, out cached))
                    {
                        if (cached.IsThreat) Handle(new ScanResult { Path = path, Sha256 = j.Sha256, Size = j.Size, Verdict = cached.Verdict, Threat = cached.Threat, Detail = cached.Detail });
                        continue;
                    }
                }
                jobs.Add(j);
            }
            if (jobs.Count == 0) return;

            List<ScanResult> results;
            using (var cloud = new CloudClient(settings))
            {
                cloud.Connect();
                results = cloud.Scan(jobs, null, () => !running);
            }
            foreach (ScanResult r in results)
            {
                if (r.Verdict != "error")
                    lock (sync) verdictCache[r.Sha256] = r;
                Log.Write("real-time: " + r.Verdict + "  " + r.Path + (r.Threat.Length > 0 ? "  " + r.Threat : ""));
                if (r.IsThreat) Handle(r);
            }
        }

        private void Handle(ScanResult r)
        {
            bool quarantined = false;
            if (settings.AutoQuarantine && r.Verdict == "malicious")
            {
                try
                {
                    Quarantine.Add(r.Path, r.Sha256, r.Threat);
                    quarantined = true;
                }
                catch (Exception e)
                {
                    Log.Write("real-time: could not quarantine " + r.Path + ": " + e.Message);
                }
            }
            Action<ScanResult, bool> h = ThreatFound;
            if (h != null) h(r, quarantined);
        }

        public void Dispose()
        {
            Stop();
        }
    }
}
