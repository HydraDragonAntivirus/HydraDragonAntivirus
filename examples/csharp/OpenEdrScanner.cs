using System;
using System.Runtime.InteropServices;

namespace OpenEdr.Sdk
{
    public enum FlsVerdict
    {
        Error = -1,
        Unknown = 0,
        Safe = 1,
        Malicious = 2
    }

    public class OpenEdrScanner : IDisposable
    {
        private const string DllName = "openedr_static.dll";

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int openedr_static_init(string baseRulesDir);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern IntPtr openedr_static_scan_file(string filePath);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern IntPtr openedr_static_scan_bytes(byte[] data, UIntPtr len, string fileName);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern IntPtr openedr_static_scan_url(string url);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern IntPtr openedr_static_check_registry(string regPath);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int openedr_static_check_fls_sha1(string sha1Hex);

        [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
        private static extern void openedr_static_free_string(IntPtr s);

        public OpenEdrScanner(string rulesDir = null)
        {
            int res = openedr_static_init(rulesDir);
            if (res != 0)
            {
                throw new InvalidOperationException($"Failed to initialize OpenEDR Static Engine (code: {res})");
            }
        }

        private static string PtrToStringAndFree(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero) return null;
            try
            {
                return Marshal.PtrToStringAnsi(ptr);
            }
            finally
            {
                openedr_static_free_string(ptr);
            }
        }

        public string ScanFile(string filePath)
        {
            if (string.IsNullOrEmpty(filePath)) throw new ArgumentNullException(nameof(filePath));
            IntPtr ptr = openedr_static_scan_file(filePath);
            return PtrToStringAndFree(ptr);
        }

        public string ScanBytes(byte[] data, string virtualName = "sample.bin")
        {
            if (data == null || data.Length == 0) throw new ArgumentException("Data cannot be empty", nameof(data));
            IntPtr ptr = openedr_static_scan_bytes(data, (UIntPtr)data.Length, virtualName);
            return PtrToStringAndFree(ptr);
        }

        public string ScanUrl(string url)
        {
            if (string.IsNullOrEmpty(url)) throw new ArgumentNullException(nameof(url));
            IntPtr ptr = openedr_static_scan_url(url);
            return PtrToStringAndFree(ptr);
        }

        public string CheckRegistry(string regPath)
        {
            if (string.IsNullOrEmpty(regPath)) throw new ArgumentNullException(nameof(regPath));
            IntPtr ptr = openedr_static_check_registry(regPath);
            return PtrToStringAndFree(ptr);
        }

        public FlsVerdict QueryFls(string sha1Hex)
        {
            if (string.IsNullOrEmpty(sha1Hex)) throw new ArgumentNullException(nameof(sha1Hex));
            int code = openedr_static_check_fls_sha1(sha1Hex);
            return (FlsVerdict)code;
        }

        public void Dispose()
        {
            // Engine memory managed by Rust OnceLock
        }
    }
}
