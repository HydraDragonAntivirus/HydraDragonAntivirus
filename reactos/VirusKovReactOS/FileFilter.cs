using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;

namespace VirusKov.ReactOS
{
    /// <summary>
    /// Which files are sent (same rule as Multron Win Cleaner's "Only executables &amp;
    /// scripts" filter, see the EULA) and how folder paths are made anonymous.
    /// </summary>
    public static class FileFilter
    {
        private static readonly Dictionary<string, bool> Executable = Set(
            ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv", ".msi", ".msp",
            ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".jar", ".lnk",
            ".pif", ".vxd", ".386", ".inf", ".reg");

        // Never executable: skipped without opening them (opening every file of a whole
        // disk for the MZ check is what makes a full scan slow).
        private static readonly Dictionary<string, bool> NonExecutable = Set(
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".ico", ".svg", ".psd", ".raw",
            ".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a", ".wma", ".mp4", ".mkv", ".avi", ".mov", ".wmv", ".webm", ".mpg",
            ".txt", ".log", ".md", ".csv", ".json", ".xml", ".yml", ".yaml", ".html", ".htm", ".css", ".ini", ".nls", ".mui",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".rtf", ".chm", ".hlp",
            ".ttf", ".otf", ".fon", ".fnt", ".woff", ".woff2", ".etl", ".evt", ".evtx", ".cat", ".manifest", ".pnf");

        private static Dictionary<string, bool> Set(params string[] items)
        {
            var d = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            foreach (string i in items) d[i] = true;
            return d;
        }

        public static bool IsExecutable(string path)
        {
            string ext = Path.GetExtension(path);
            if (Executable.ContainsKey(ext))
                return true;
            if (NonExecutable.ContainsKey(ext))
                return false;
            return HasMzHeader(path);
        }

        private static bool HasMzHeader(string path)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 16))
                    return fs.ReadByte() == 'M' && fs.ReadByte() == 'Z';
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>SHA-256 (lower-case hex) of a file, streamed. Null when unreadable.</summary>
        public static string Sha256(string path)
        {
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 1 << 20))
                using (HashAlgorithm sha = NewSha256())
                {
                    byte[] h = sha.ComputeHash(fs);
                    return BitConverter.ToString(h).Replace("-", "").ToLowerInvariant();
                }
            }
            catch (Exception)
            {
                return null;
            }
        }

        private static int cspState; // 0 = untested, 1 = works, 2 = not available

        /// <summary>
        /// The operating system's SHA-256 (CryptoAPI) when it has one: several times faster
        /// than the managed code, which matters on old CPUs and in an emulator. Windows 9x and
        /// some ReactOS builds have no SHA-256 provider, then the managed one is used.
        /// </summary>
        private static HashAlgorithm NewSha256()
        {
            if (cspState != 2)
            {
                try
                {
                    HashAlgorithm h = new SHA256CryptoServiceProvider();
                    if (cspState == 0)
                    {
                        h.ComputeHash(new byte[] { 1 });
                        h = new SHA256CryptoServiceProvider();
                        cspState = 1;
                    }
                    return h;
                }
                catch (Exception)
                {
                    cspState = 2;
                }
            }
            return new SHA256Managed();
        }

        private static List<KeyValuePair<string, string>> placeholders;

        /// <summary>
        /// Folder of a file as sent to the server (EULA section 2): the user profile and other
        /// standard folders become placeholders such as %USERPROFILE%\Downloads, so no
        /// user name is sent.
        /// </summary>
        public static string NormalizeFolder(string filePath)
        {
            try
            {
                string dir = Path.GetDirectoryName(Path.GetFullPath(filePath));
                if (string.IsNullOrEmpty(dir)) return "";
                dir = dir.TrimEnd('\\', '/');
                foreach (KeyValuePair<string, string> p in Placeholders())
                {
                    if (dir.Equals(p.Value, StringComparison.OrdinalIgnoreCase))
                        return p.Key;
                    if (dir.StartsWith(p.Value + "\\", StringComparison.OrdinalIgnoreCase))
                        return Trim260(p.Key + dir.Substring(p.Value.Length));
                }
                // Another user's profile: X:\Documents and Settings\<user> or X:\Users\<user>.
                foreach (string root in new[] { "\\Documents and Settings\\", "\\Users\\" })
                {
                    if (dir.Length > 2 && dir[1] == ':' && dir.Substring(2).StartsWith(root, StringComparison.OrdinalIgnoreCase))
                    {
                        int start = 2 + root.Length;
                        int end = dir.IndexOf('\\', start);
                        string user = end < 0 ? dir.Substring(start) : dir.Substring(start, end - start);
                        if (user.Length > 0 && !user.Equals("Public", StringComparison.OrdinalIgnoreCase)
                            && !user.Equals("All Users", StringComparison.OrdinalIgnoreCase)
                            && !user.Equals("Default", StringComparison.OrdinalIgnoreCase)
                            && !user.Equals("Default User", StringComparison.OrdinalIgnoreCase))
                            return Trim260("%USERPROFILE%" + (end < 0 ? "" : dir.Substring(end)));
                    }
                }
                return Trim260(dir);
            }
            catch (Exception)
            {
                return "";
            }
        }

        private static string Trim260(string s)
        {
            return s.Length > 260 ? s.Substring(0, 260) : s;
        }

        private static List<KeyValuePair<string, string>> Placeholders()
        {
            if (placeholders != null) return placeholders;
            var l = new List<KeyValuePair<string, string>>();
            Add(l, "%TEMP%", Path.GetTempPath());
            Add(l, "%LOCALAPPDATA%", Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
            Add(l, "%APPDATA%", Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
            Add(l, "%USERPROFILE%", Platform.Env("USERPROFILE"));
            Add(l, "%PROGRAMFILES(X86)%", Platform.Env("ProgramFiles(x86)"));
            Add(l, "%PROGRAMFILES%", Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            Add(l, "%PROGRAMDATA%", Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
            Add(l, "%WINDIR%", Platform.Env("WINDIR") ?? Platform.Env("SystemRoot"));
            l.Sort((a, b) => b.Value.Length.CompareTo(a.Value.Length)); // longest first
            placeholders = l;
            return l;
        }

        private static void Add(List<KeyValuePair<string, string>> l, string name, string value)
        {
            if (!string.IsNullOrEmpty(value) && value.Trim().Length > 0)
                l.Add(new KeyValuePair<string, string>(name, value.TrimEnd('\\', '/')));
        }
    }
}
