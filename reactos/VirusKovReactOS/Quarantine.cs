using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace VirusKov.ReactOS
{
    public sealed class QuarantineItem
    {
        public string Id;
        public string OriginalPath;
        public string Sha256;
        public string Threat;
        public DateTime Date;
    }

    /// <summary>
    /// Moves a file into data\quarantine, XOR-scrambled so it cannot run and other
    /// scanners do not keep flagging it, with a small .txt next to it describing it.
    /// </summary>
    public static class Quarantine
    {
        private const byte Key = 0x5A;

        public static QuarantineItem Add(string path, string sha256, string threat)
        {
            string id = Guid.NewGuid().ToString("N");
            string blob = Path.Combine(AppPaths.QuarantineDir, id + ".vkq");
            using (var src = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var dst = new FileStream(blob, FileMode.CreateNew, FileAccess.Write))
                Xor(src, dst);
            var item = new QuarantineItem { Id = id, OriginalPath = path, Sha256 = sha256 ?? "", Threat = threat ?? "", Date = DateTime.Now };
            File.WriteAllText(Path.Combine(AppPaths.QuarantineDir, id + ".txt"),
                "path=" + item.OriginalPath + "\r\nsha256=" + item.Sha256 + "\r\nthreat=" + item.Threat +
                "\r\ndate=" + item.Date.ToString("s", CultureInfo.InvariantCulture) + "\r\n", Encoding.UTF8);
            try
            {
                File.SetAttributes(path, FileAttributes.Normal);
                File.Delete(path);
            }
            catch (Exception)
            {
                // The copy is kept; tell the caller the original is still there.
                File.Delete(blob);
                File.Delete(Path.Combine(AppPaths.QuarantineDir, id + ".txt"));
                throw;
            }
            Log.Write("quarantined: " + path + " (" + threat + ")");
            return item;
        }

        public static List<QuarantineItem> List()
        {
            var l = new List<QuarantineItem>();
            foreach (string txt in Directory.GetFiles(AppPaths.QuarantineDir, "*.txt"))
            {
                var item = new QuarantineItem { Id = Path.GetFileNameWithoutExtension(txt) };
                foreach (string line in File.ReadAllLines(txt, Encoding.UTF8))
                {
                    int eq = line.IndexOf('=');
                    if (eq <= 0) continue;
                    string k = line.Substring(0, eq), v = line.Substring(eq + 1);
                    if (k == "path") item.OriginalPath = v;
                    else if (k == "sha256") item.Sha256 = v;
                    else if (k == "threat") item.Threat = v;
                    else if (k == "date") DateTime.TryParse(v, CultureInfo.InvariantCulture, DateTimeStyles.None, out item.Date);
                }
                l.Add(item);
            }
            l.Sort((a, b) => b.Date.CompareTo(a.Date));
            return l;
        }

        /// <summary>Puts the file back where it was (or into <paramref name="target"/>).</summary>
        public static void Restore(QuarantineItem item, string target)
        {
            string blob = Path.Combine(AppPaths.QuarantineDir, item.Id + ".vkq");
            string dest = target ?? item.OriginalPath;
            Directory.CreateDirectory(Path.GetDirectoryName(dest));
            using (var src = File.OpenRead(blob))
            using (var dst = new FileStream(dest, FileMode.CreateNew, FileAccess.Write))
                Xor(src, dst);
            Delete(item);
            Log.Write("restored from quarantine: " + dest);
        }

        public static void Delete(QuarantineItem item)
        {
            File.Delete(Path.Combine(AppPaths.QuarantineDir, item.Id + ".vkq"));
            File.Delete(Path.Combine(AppPaths.QuarantineDir, item.Id + ".txt"));
        }

        private static void Xor(Stream src, Stream dst)
        {
            var buf = new byte[65536];
            int n;
            while ((n = src.Read(buf, 0, buf.Length)) > 0)
            {
                for (int i = 0; i < n; i++) buf[i] ^= Key;
                dst.Write(buf, 0, n);
            }
        }
    }
}
