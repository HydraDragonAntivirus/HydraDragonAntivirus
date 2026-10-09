using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace VirusKov.ReactOS
{
    public enum BootSectorState
    {
        Unsupported,     // Windows 9x: no raw disk access from user mode
        NoBackup,
        Ok,
        BootCodeChanged, // MBR boot code (bytes 0-439): what bootkits and MBR wipers rewrite
        PartitionTableChanged,
        HiddenSectorsChanged, // sectors 1-62 ("track 0"), where bootkits hide their payload
        Error,
    }

    /// <summary>
    /// Boot sector backup and check, like the first VirusKov project in 2023: the first 63
    /// sectors of the boot disk (MBR + track 0) are saved once, then compared at every
    /// start. A change is reported; restoring writes back only the boot code (the current
    /// partition table is kept, so a legitimate repartition is never undone) and, if asked,
    /// track 0. Raw disk access needs CreateFile on \\.\PhysicalDrive0 (the only P/Invoke
    /// in the program; .NET refuses device paths) and administrator rights. NT only:
    /// ReactOS, Windows 2000/XP and later.
    /// </summary>
    public static class BootSectorGuard
    {
        private const int SectorSize = 512;
        private const int Sectors = 63;
        private const string Disk = @"\\.\PhysicalDrive0";

        public static string BackupPath
        {
            get { return Path.Combine(AppPaths.DataDir, "bootsector_drive0.bin"); }
        }

        public static byte[] ReadDisk()
        {
            using (FileStream fs = Open(false))
            {
                var buf = new byte[SectorSize * Sectors];
                int got = 0;
                while (got < buf.Length)
                {
                    int n = fs.Read(buf, got, buf.Length - got);
                    if (n <= 0) break;
                    got += n;
                }
                if (got < SectorSize) throw new IOException("Could not read the boot sector.");
                if (got < buf.Length) Array.Resize(ref buf, got - got % SectorSize);
                return buf;
            }
        }

        public static void Backup()
        {
            byte[] data = ReadDisk();
            string tmp = BackupPath + ".tmp";
            File.WriteAllBytes(tmp, data);
            if (File.Exists(BackupPath)) File.Delete(BackupPath);
            File.Move(tmp, BackupPath);
            Log.Write("boot sector backup saved (" + data.Length / SectorSize + " sectors, MBR sha256 " + Sha(data, 0, SectorSize) + ")");
        }

        public static BootSectorState Check(out string detail)
        {
            detail = "";
            if (!Platform.IsNT)
            {
                detail = "Windows 9x has no raw disk access for programs; boot sector protection is not available.";
                return BootSectorState.Unsupported;
            }
            if (!File.Exists(BackupPath))
            {
                detail = "No backup yet.";
                return BootSectorState.NoBackup;
            }
            try
            {
                byte[] saved = File.ReadAllBytes(BackupPath);
                byte[] now = ReadDisk();
                if (!Same(saved, now, 0, 440))
                {
                    detail = "The MBR boot code changed (sha256 now " + Sha(now, 0, SectorSize) + "). Bootkits and MBR wipers do this. If you did not reinstall a boot loader, restore the boot code.";
                    return BootSectorState.BootCodeChanged;
                }
                if (!Same(saved, now, 440, 72))
                {
                    detail = "The partition table or disk signature changed. Normal after repartitioning; otherwise investigate.";
                    return BootSectorState.PartitionTableChanged;
                }
                int len = Math.Min(saved.Length, now.Length);
                if (len > SectorSize && !Same(saved, now, SectorSize, len - SectorSize))
                {
                    detail = "Hidden sectors after the MBR (track 0) changed. Some boot managers write there; bootkits hide there too.";
                    return BootSectorState.HiddenSectorsChanged;
                }
                detail = "Boot sector matches the backup.";
                return BootSectorState.Ok;
            }
            catch (Exception e)
            {
                detail = e is UnauthorizedAccessException || e is Win32Exception
                    ? "Run as administrator to read the boot sector (" + e.Message + ")."
                    : e.Message;
                return BootSectorState.Error;
            }
        }

        /// <summary>
        /// Writes the saved boot code back. The partition table and disk signature currently
        /// on disk are kept. With <paramref name="includeTrack0"/> sectors 1-62 are restored too.
        /// </summary>
        public static void RestoreBootCode(bool includeTrack0)
        {
            byte[] saved = File.ReadAllBytes(BackupPath);
            byte[] now = ReadDisk();
            var sector0 = new byte[SectorSize];
            Buffer.BlockCopy(now, 0, sector0, 0, SectorSize);
            Buffer.BlockCopy(saved, 0, sector0, 0, 440); // boot code only; 440-445 = disk signature, 446+ = partition table
            sector0[510] = 0x55;
            sector0[511] = 0xAA;
            int length = SectorSize;
            byte[] write = sector0;
            if (includeTrack0 && saved.Length > SectorSize)
            {
                length = Math.Min(saved.Length, now.Length);
                write = new byte[length];
                Buffer.BlockCopy(saved, 0, write, 0, length);
                Buffer.BlockCopy(sector0, 0, write, 0, SectorSize);
            }
            using (FileStream fs = Open(true))
            {
                fs.Write(write, 0, length);
                fs.Flush();
            }
            Log.Write("boot code restored from backup" + (includeTrack0 ? " (with track 0)" : ""));
        }

        private static bool Same(byte[] a, byte[] b, int offset, int count)
        {
            if (a.Length < offset + count || b.Length < offset + count) return false;
            for (int i = offset; i < offset + count; i++)
                if (a[i] != b[i]) return false;
            return true;
        }

        private static string Sha(byte[] data, int offset, int count)
        {
            using (var sha = new SHA256Managed())
                return BitConverter.ToString(sha.ComputeHash(data, offset, count)).Replace("-", "").ToLowerInvariant();
        }

        // ---------------- raw disk access ----------------

        private const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000;
        private const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, OPEN_EXISTING = 3;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security,
            uint creation, uint flags, IntPtr template);

        private static FileStream Open(bool write)
        {
            SafeFileHandle h = CreateFile(Disk, write ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (h.IsInvalid)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            // Sector-sized buffer: raw disk I/O must be sector aligned.
            return new FileStream(h, write ? FileAccess.ReadWrite : FileAccess.Read, SectorSize);
        }
    }
}
