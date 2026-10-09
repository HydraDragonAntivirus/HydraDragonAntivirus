using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

namespace VirusKov.ReactOS
{
    /// <summary>
    /// On-demand scan of several locations: collect the files (minus exclusions), hash them
    /// (cached by path + size + date, so a second scan only hashes what changed), then ask
    /// the cloud. Reports progress for every phase.
    /// </summary>
    public sealed class Scanner
    {
        private readonly Settings settings;
        private volatile bool cancel;
        private readonly Stopwatch throttle = Stopwatch.StartNew();

        /// <summary>Status line.</summary>
        public event Action<string> Status;
        /// <summary>Progress 0..1000 of the current phase.</summary>
        public event Action<int> Progress;

        public Scanner(Settings settings)
        {
            this.settings = settings;
        }

        public void Cancel()
        {
            cancel = true;
        }

        private void Say(string s, bool force)
        {
            if (!force && throttle.ElapsedMilliseconds < 200) return;
            throttle.Reset();
            throttle.Start();
            Action<string> h = Status;
            if (h != null) h(s);
        }

        private void Bar(long done, long total)
        {
            Action<int> h = Progress;
            if (h != null) h(total <= 0 ? 0 : (int)Math.Min(1000, done * 1000 / total));
        }

        public List<ScanResult> Run(IList<string> targets)
        {
            cancel = false;
            var exclusions = new Exclusions(settings.ExcludeList());
            long maxBytes = settings.MaxScanMB > 0 ? (long)settings.MaxScanMB * 1024 * 1024 : long.MaxValue;

            // 1. Collect
            var files = new List<FileInfo>();
            var seen = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            Bar(0, 1);
            foreach (string t in targets)
            {
                if (cancel) break;
                if (File.Exists(t)) AddFile(new FileInfo(t), files, seen, exclusions, maxBytes);
                else if (Directory.Exists(t)) Collect(new DirectoryInfo(t), files, seen, exclusions, maxBytes, 0);
                else Log.Write("scan: not found: " + t);
            }
            Say("Found " + files.Count + " file(s) to check.", true);

            // 2. Hash (cache hits are instant)
            var results = new List<ScanResult>();
            var jobs = new List<FileJob>();
            long totalBytes = 0, doneBytes = 0;
            foreach (FileInfo f in files) totalBytes += f.Length;
            var cache = HashCache.Load();
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < files.Count && !cancel; i++)
            {
                FileInfo f = files[i];
                double mbs = sw.Elapsed.TotalSeconds > 0.5 ? doneBytes / 1048576.0 / sw.Elapsed.TotalSeconds : 0;
                Say("Hashing " + (i + 1) + " / " + files.Count + "  (" + Size(doneBytes) + " of " + Size(totalBytes) +
                    (mbs > 0 ? ", " + mbs.ToString("0.0") + " MB/s" : "") + ")  " + f.FullName, false);
                string sha = cache.Get(f);
                if (sha == null)
                {
                    sha = FileFilter.Sha256(f.FullName);
                    if (sha != null) cache.Put(f, sha);
                }
                doneBytes += f.Length;
                Bar(doneBytes, totalBytes);
                if (sha == null)
                {
                    results.Add(new ScanResult { Path = f.FullName, Size = f.Length, Verdict = "error", Detail = "Could not read the file (in use or no access)" });
                    continue;
                }
                if (f.Length == 0) continue;
                jobs.Add(new FileJob { Path = f.FullName, Sha256 = sha, Size = f.Length });
            }
            cache.Save();
            if (jobs.Count == 0 || cancel)
            {
                Say(cancel ? "Scan stopped." : "Nothing to send.", true);
                return results;
            }

            // 3. Cloud
            Say("Connecting to the VirusKov cloud...", true);
            Bar(0, 1);
            using (var cloud = new CloudClient(settings))
            {
                cloud.Connect();
                long max = (long)cloud.MaxMB * 1024 * 1024;
                foreach (FileJob j in jobs)
                    if (j.Size > max)
                        results.Add(new ScanResult { Path = j.Path, Sha256 = j.Sha256, Size = j.Size, Verdict = "error", Detail = "Larger than the server limit (" + cloud.MaxMB + " MB), not sent" });
                jobs.RemoveAll(j => j.Size > max);
                results.AddRange(cloud.Scan(jobs, (d, t) =>
                {
                    Bar(d, t);
                    Say("Checking " + d + " / " + t + " in the cloud...", false);
                }, () => cancel));
            }
            int threats = results.FindAll(r => r.IsThreat).Count;
            Say(cancel ? "Scan stopped." : "Scan finished: " + results.Count + " file(s), " + threats + " threat(s).", true);
            Bar(1, 1);
            Log.Write("scan: " + results.Count + " files, " + threats + " threats");
            return results;
        }

        private static string Size(long b)
        {
            if (b < 1048576) return (b / 1024) + " KB";
            if (b < 1073741824) return (b / 1048576.0).ToString("0.0") + " MB";
            return (b / 1073741824.0).ToString("0.00") + " GB";
        }

        private void AddFile(FileInfo f, List<FileInfo> files, Dictionary<string, bool> seen, Exclusions ex, long maxBytes)
        {
            try
            {
                if (seen.ContainsKey(f.FullName)) return;
                seen[f.FullName] = true;
                if (ex.Excluded(f.FullName)) return;
                if (f.Length > maxBytes) return;
                if (settings.ExecutablesOnly && !FileFilter.IsExecutable(f.FullName)) return;
                files.Add(f);
            }
            catch (Exception) { }
        }

        private void Collect(DirectoryInfo dir, List<FileInfo> files, Dictionary<string, bool> seen, Exclusions ex, long maxBytes, int depth)
        {
            if (cancel || depth > 40) return;
            try
            {
                // Junctions / symbolic links: skip, they loop or point at other drives.
                if (depth > 0 && (dir.Attributes & FileAttributes.ReparsePoint) != 0) return;
                if (ex.Excluded(dir.FullName)) return;
                Say("Collecting (" + files.Count + " found): " + dir.FullName, false);
                foreach (FileInfo f in dir.GetFiles())
                {
                    if (cancel) return;
                    AddFile(f, files, seen, ex, maxBytes);
                }
                foreach (DirectoryInfo d in dir.GetDirectories())
                    Collect(d, files, seen, ex, maxBytes, depth + 1);
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        public static FileJob MakeJob(string path)
        {
            try
            {
                var fi = new FileInfo(path);
                string sha = FileFilter.Sha256(path);
                if (sha == null) return null;
                return new FileJob { Path = fi.FullName, Sha256 = sha, Size = fi.Length };
            }
            catch (Exception)
            {
                return null;
            }
        }
    }

    /// <summary>
    /// Exclusions: a line with a drive or a backslash is a folder (everything under it is
    /// skipped), anything else is a file name pattern with * and ? (e.g. *.iso). The
    /// program's own data folder (quarantine!) is always excluded.
    /// </summary>
    public sealed class Exclusions
    {
        private readonly List<string> folders = new List<string>();
        private readonly List<string> patterns = new List<string>();

        public static readonly string[] Defaults =
        {
            "\\System Volume Information",
            "\\RECYCLER",
            "\\$Recycle.Bin",
            "pagefile.sys",
            "hiberfil.sys",
            "swapfile.sys",
        };

        public Exclusions(IList<string> lines)
        {
            folders.Add(AppPaths.DataDir.TrimEnd('\\'));
            foreach (string raw in lines)
            {
                string l = raw.Trim().Replace('/', '\\').TrimEnd('\\');
                if (l.Length == 0) continue;
                if (l.IndexOf('\\') >= 0 || l.IndexOf(':') >= 0) folders.Add(l);
                else patterns.Add(l);
            }
        }

        public bool Excluded(string path)
        {
            string name = Path.GetFileName(path);
            path = path.Replace('/', '\\');
            foreach (string f0 in folders)
            {
                string f = f0.Replace('/', '\\');
                if (f.StartsWith("\\") && !f.StartsWith("\\\\"))
                {
                    // "\RECYCLER": that folder name on any drive.
                    int i = path.IndexOf(f, StringComparison.OrdinalIgnoreCase);
                    if (i >= 0 && (path.Length == i + f.Length || path[i + f.Length] == '\\')) return true;
                }
                else if (path.Equals(f, StringComparison.OrdinalIgnoreCase) || path.StartsWith(f + "\\", StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            foreach (string p in patterns)
                if (Wildcard(name, p)) return true;
            return false;
        }

        public static bool Wildcard(string text, string pattern)
        {
            int t = 0, p = 0, star = -1, mark = 0;
            while (t < text.Length)
            {
                if (p < pattern.Length && (pattern[p] == '?' || char.ToLowerInvariant(pattern[p]) == char.ToLowerInvariant(text[t]))) { t++; p++; }
                else if (p < pattern.Length && pattern[p] == '*') { star = p++; mark = t; }
                else if (star >= 0) { p = star + 1; t = ++mark; }
                else return false;
            }
            while (p < pattern.Length && pattern[p] == '*') p++;
            return p == pattern.Length;
        }
    }

    /// <summary>path|size|ticks -> sha256, so unchanged files are not hashed again.</summary>
    public sealed class HashCache
    {
        private readonly Dictionary<string, string> map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private bool dirty;

        private static string FilePath
        {
            get { return Path.Combine(AppPaths.DataDir, "hashcache.txt"); }
        }

        private static string Key(FileInfo f)
        {
            return f.FullName + "|" + f.Length + "|" + f.LastWriteTimeUtc.Ticks;
        }

        public static HashCache Load()
        {
            var c = new HashCache();
            try
            {
                if (File.Exists(FilePath))
                    foreach (string line in File.ReadAllLines(FilePath))
                    {
                        int tab = line.LastIndexOf('\t');
                        if (tab > 0) c.map[line.Substring(0, tab)] = line.Substring(tab + 1);
                    }
            }
            catch (Exception) { }
            return c;
        }

        public string Get(FileInfo f)
        {
            string sha;
            return map.TryGetValue(Key(f), out sha) ? sha : null;
        }

        public void Put(FileInfo f, string sha)
        {
            map[Key(f)] = sha;
            dirty = true;
        }

        public void Save()
        {
            if (!dirty) return;
            try
            {
                using (var w = new StreamWriter(FilePath, false, System.Text.Encoding.UTF8))
                {
                    int n = 0;
                    foreach (KeyValuePair<string, string> e in map)
                    {
                        if (++n > 500000) break; // keep the file bounded
                        w.Write(e.Key);
                        w.Write('\t');
                        w.WriteLine(e.Value);
                    }
                }
            }
            catch (Exception) { }
        }
    }
}
