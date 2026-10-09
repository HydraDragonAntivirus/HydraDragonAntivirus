using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

namespace VirusKov.ReactOS
{
    public static class AppInfo
    {
        public static string Version
        {
            get
            {
                Version v = Assembly.GetExecutingAssembly().GetName().Version;
                return v.Major + "." + v.Minor + "." + v.Build;
            }
        }

        /// <summary>Client name sent in the hello message (shown on the server dashboard).</summary>
        public static string ClientName
        {
            get { return "VirusKovReactOS/" + Version + " (" + Environment.OSVersion.VersionString + ")"; }
        }
    }

    /// <summary>
    /// Portable layout: everything lives next to the program (settings, log, quarantine,
    /// boot sector backups), so it runs from a USB stick on ReactOS / XP / 9x as well.
    /// </summary>
    public static class AppPaths
    {
        public static string ProgramDir
        {
            get { return Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location); }
        }

        public static string DataDir
        {
            get
            {
                string d = Path.Combine(ProgramDir, "data");
                Directory.CreateDirectory(d);
                return d;
            }
        }

        public static string QuarantineDir
        {
            get
            {
                string d = Path.Combine(DataDir, "quarantine");
                Directory.CreateDirectory(d);
                return d;
            }
        }
    }

    public static class Log
    {
        private static readonly object Sync = new object();
        public static event Action<string> Written;

        public static void Write(string message)
        {
            string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + message;
            lock (Sync)
            {
                try
                {
                    string path = Path.Combine(AppPaths.DataDir, "viruskov.log");
                    var fi = new FileInfo(path);
                    if (fi.Exists && fi.Length > 2 * 1024 * 1024)
                    {
                        string old = path + ".1";
                        if (File.Exists(old)) File.Delete(old);
                        File.Move(path, old);
                    }
                    File.AppendAllText(path, line + "\r\n", Encoding.UTF8);
                }
                catch (Exception) { }
            }
            Action<string> h = Written;
            if (h != null)
            {
                try { h(line); } catch (Exception) { }
            }
        }
    }

    /// <summary>key=value settings in data\settings.txt.</summary>
    public sealed class Settings
    {
        public const string DefaultServerUrl = "wss://api.viruskov.com/ws";

        public string ServerUrl = DefaultServerUrl;
        public string Token = "";
        public bool ExecutablesOnly = true;
        public bool RealtimeEnabled = true;
        /// <summary>Malicious files found by real-time protection go to quarantine without asking.</summary>
        public bool AutoQuarantine = true;
        public bool StartWithWindows = false;
        public int EulaAccepted = 0;
        /// <summary>Extra folders for real-time protection, separated by '|'.</summary>
        public string ExtraFolders = "";
        /// <summary>Locations of the last on-demand scan, separated by '|'.</summary>
        public string ScanTargets = "";
        /// <summary>Scan exclusions (folders or file name patterns), separated by '|'.</summary>
        public string Excludes = string.Join("|", Exclusions.Defaults);
        /// <summary>Skip files larger than this on a scan (MB, 0 = only the server limit).</summary>
        public int MaxScanMB = 0;

        private static string FilePath
        {
            get { return Path.Combine(AppPaths.DataDir, "settings.txt"); }
        }

        public static Settings Load()
        {
            var s = new Settings();
            if (!File.Exists(FilePath))
                return s;
            foreach (string raw in File.ReadAllLines(FilePath, Encoding.UTF8))
            {
                int eq = raw.IndexOf('=');
                if (eq <= 0) continue;
                string k = raw.Substring(0, eq).Trim(), v = raw.Substring(eq + 1).Trim();
                switch (k)
                {
                    case "ServerUrl": if (v.Length > 0) s.ServerUrl = v; break;
                    case "Token": s.Token = v; break;
                    case "ExecutablesOnly": s.ExecutablesOnly = v == "1"; break;
                    case "RealtimeEnabled": s.RealtimeEnabled = v == "1"; break;
                    case "AutoQuarantine": s.AutoQuarantine = v == "1"; break;
                    case "StartWithWindows": s.StartWithWindows = v == "1"; break;
                    case "EulaAccepted": int.TryParse(v, out s.EulaAccepted); break;
                    case "ExtraFolders": s.ExtraFolders = v; break;
                    case "ScanTargets": s.ScanTargets = v; break;
                    case "Excludes": s.Excludes = v; break;
                    case "MaxScanMB": int.TryParse(v, out s.MaxScanMB); break;
                }
            }
            return s;
        }

        public void Save()
        {
            var sb = new StringBuilder();
            sb.Append("ServerUrl=").Append(ServerUrl).Append("\r\n");
            sb.Append("Token=").Append(Token).Append("\r\n");
            sb.Append("ExecutablesOnly=").Append(ExecutablesOnly ? "1" : "0").Append("\r\n");
            sb.Append("RealtimeEnabled=").Append(RealtimeEnabled ? "1" : "0").Append("\r\n");
            sb.Append("AutoQuarantine=").Append(AutoQuarantine ? "1" : "0").Append("\r\n");
            sb.Append("StartWithWindows=").Append(StartWithWindows ? "1" : "0").Append("\r\n");
            sb.Append("EulaAccepted=").Append(EulaAccepted).Append("\r\n");
            sb.Append("ExtraFolders=").Append(ExtraFolders).Append("\r\n");
            sb.Append("ScanTargets=").Append(ScanTargets).Append("\r\n");
            sb.Append("Excludes=").Append(Excludes).Append("\r\n");
            sb.Append("MaxScanMB=").Append(MaxScanMB).Append("\r\n");
            File.WriteAllText(FilePath, sb.ToString(), Encoding.UTF8);
        }

        public List<string> ExtraFolderList()
        {
            return Split(ExtraFolders);
        }

        public List<string> ScanTargetList()
        {
            return Split(ScanTargets);
        }

        public List<string> ExcludeList()
        {
            return Split(Excludes);
        }

        private static List<string> Split(string v)
        {
            var l = new List<string>();
            foreach (string f in (v ?? "").Split('|'))
                if (f.Trim().Length > 0) l.Add(f.Trim());
            return l;
        }
    }

    public static class Platform
    {
        /// <summary>NT kernel (ReactOS, XP and later). False on Windows 95/98/ME.</summary>
        public static bool IsNT
        {
            get { return Environment.OSVersion.Platform == PlatformID.Win32NT; }
        }

        public static string Env(string name)
        {
            string v = Environment.GetEnvironmentVariable(name);
            return string.IsNullOrEmpty(v) ? null : v.TrimEnd('\\', '/');
        }
    }
}
