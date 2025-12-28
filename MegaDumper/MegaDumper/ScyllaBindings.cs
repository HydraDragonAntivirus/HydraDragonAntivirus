/*
 * ScyllaBindings.cs
 * Final fixed version for Scylla Import Reconstruction DLL (x64)
 * Protected with CSE attributes and uint-based marshaling for .NET 8.
 */

using System;
using System.Runtime.InteropServices;
using System.IO;
using System.Runtime.ExceptionServices;

namespace MegaDumper
{
    public enum ScyllaError : int
    {
        Success = 0,
        ProcessOpenFailed = -1,
        IatWriteError = -2,
        IatSearchError = -3,
        IatNotFound = -4,
        PidNotFound = -5,
        ModuleNotFound = -6
    }

    public static class ScyllaBindings
    {
        private const string SCYLLA_DLL_X64 = "Scylla.dll";

        public static bool IsAvailable
        {
            get
            {
                try
                {
                    var version = VersionInformation();
                    return !string.IsNullOrEmpty(version);
                }
                catch
                {
                    return false;
                }
            }
        }
        
        public static string LastLoadError { get; set; } = string.Empty;

        #region Native Imports

        [DllImport("Scylla.dll", EntryPoint = "ScyllaVersionInformationW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr ScyllaVersionInformationW_x64();

        // PID is DWORD (4 bytes), advancedSearch is BOOL (4 bytes)
        [DllImport("Scylla.dll", EntryPoint = "ScyllaIatSearch", CallingConvention = CallingConvention.StdCall)]
        private static extern int ScyllaIatSearch_x64(
            uint dwProcessId,
            UIntPtr imagebase,
            out UIntPtr iatStart,
            out uint iatSize,
            UIntPtr searchStart,
            uint advancedSearch);

        // PID is DWORD (4 bytes)
        [DllImport("Scylla.dll", EntryPoint = "ScyllaIatFixAutoW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        private static extern int ScyllaIatFixAutoW_x64(
            uint dwProcessId,
            UIntPtr imagebase,
            UIntPtr iatAddr,
            uint iatSize,
            uint createNewIat,
            [MarshalAs(UnmanagedType.LPWStr)] string dumpFile,
            [MarshalAs(UnmanagedType.LPWStr)] string iatFixFile);

        [DllImport("Scylla.dll", EntryPoint = "ScyllaRebuildFileW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        private static extern uint ScyllaRebuildFileW_x64(
            [MarshalAs(UnmanagedType.LPWStr)] string fileToRebuild,
            uint removeDosStub,
            uint updatePeHeaderChecksum,
            uint createBackup);

        // PID is DWORD_PTR (8 bytes on x64)
        [DllImport("Scylla.dll", EntryPoint = "ScyllaDumpProcessW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        private static extern uint ScyllaDumpProcessW_x64(
            UIntPtr pid,
            [MarshalAs(UnmanagedType.LPWStr)] string fileToDump,
            UIntPtr imagebase,
            UIntPtr entrypoint,
            [MarshalAs(UnmanagedType.LPWStr)] string fileResult);

        #endregion

        public static string VersionInformation()
        {
            try { return Marshal.PtrToStringUni(ScyllaVersionInformationW_x64()); } catch { return null; }
        }

        [System.Security.SecurityCritical]
        public static int IatSearch(uint processId, ulong imageBase, out UIntPtr iatStart, out uint iatSize, ulong searchStart, bool advancedSearch)
        {
             iatStart = UIntPtr.Zero;
             iatSize = 0;
             try {
                return ScyllaIatSearch_x64(processId, (UIntPtr)imageBase, out iatStart, out iatSize, (UIntPtr)searchStart, advancedSearch ? 1u : 0u);
             } catch { return (int)ScyllaError.IatSearchError; }
        }

        [System.Security.SecurityCritical]
        public static ScyllaError IatFix(uint processId, ulong imageBase, UIntPtr iatStart, uint iatSize, bool createNewIat, string dumpFilePath, string outputFilePath)
        {
             try {
                return (ScyllaError)ScyllaIatFixAutoW_x64(processId, (UIntPtr)imageBase, iatStart, iatSize, createNewIat ? 1u : 0u, dumpFilePath, outputFilePath);
             } catch { return ScyllaError.IatWriteError; }
        }

        [System.Security.SecurityCritical]
        public static bool RebuildFile(string filePath, bool removeDosStub, bool updatePeHeaderChecksum, bool createBackup)
        {
             try {
                return ScyllaRebuildFileW_x64(filePath, removeDosStub ? 1u : 0u, updatePeHeaderChecksum ? 1u : 0u, createBackup ? 1u : 0u) != 0;
             } catch { return false; }
        }

        public static ScyllaError FixImportsAutoDetect(
            uint processId,
            ulong imageBase,
            ulong entryPoint,
            string dumpFilePath,
            string outputFilePath,
            bool advancedSearch = true,
            bool createNewIat = true)
        {
            return FixImportsAutoX64(processId, imageBase, entryPoint, dumpFilePath, outputFilePath, advancedSearch, createNewIat);
        }


        [System.Security.SecurityCritical]
        public static ScyllaError FixImportsAutoX64(
            uint processId,
            ulong imageBase,
            ulong entryPoint,
            string dumpFilePath,
            string outputFilePath,
            bool advancedSearch = true,
            bool createNewIat = true)
        {
            try
            {
                UIntPtr outIatStart;
                uint outIatSize;
                
                int searchResult = IatSearch(processId, imageBase, out outIatStart, out outIatSize, entryPoint, advancedSearch);
                
                if (searchResult != 0) return (ScyllaError)searchResult;
                if (outIatSize == 0) return ScyllaError.IatNotFound;
                
                return IatFix(processId, imageBase, outIatStart, outIatSize, createNewIat, dumpFilePath, outputFilePath);
            }
            catch (Exception ex)
            {
                try { File.AppendAllText("scylla_error.log", $"[Exception] {DateTime.Now}: {ex.Message}\n{ex.StackTrace}\n"); } catch {}
                return ScyllaError.ProcessOpenFailed;
            }
        }

        [System.Security.SecurityCritical]
        public static bool DumpProcessX64(uint processId, ulong imageBase, ulong entryPoint, string outputPath, string inputFilePath = null)
        {
            try
            {
                return ScyllaDumpProcessW_x64((UIntPtr)processId, inputFilePath, (UIntPtr)imageBase, (UIntPtr)entryPoint, outputPath) != 0;
            }
            catch { return false; }
        }

        public static bool IsProcess32Bit(uint processId)
        {
            IntPtr hProcess = IntPtr.Zero;
            try
            {
                hProcess = OpenProcess(0x0400, false, processId);
                if (hProcess == IntPtr.Zero) return false;
                if (!Environment.Is64BitOperatingSystem) return true;
                if (!IsWow64Process(hProcess, out bool isWow64)) return false;
                return isWow64;
            }
            catch { return false; }
            finally { if (hProcess != IntPtr.Zero) CloseHandle(hProcess); }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);
    }
}
