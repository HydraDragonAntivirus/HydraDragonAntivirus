/*
 * Mega Dumper - headless dump engine.
 *
 * The process dump logic of the former WinForms MainForm, without the GUI, so
 * the tool builds with NativeAOT into one native exe that needs no .NET
 * runtime. It reads the target only through kernel32 / ntdll / psapi (memory
 * scan for PE images and .NET metadata), so the target does not have to be a
 * .NET process and nothing is loaded into it.
 */
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Mega_Dumper
{
    public sealed partial class Dumper
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            UIntPtr nSize,
            out UIntPtr lpNumberOfBytesRead
        );

        // This is now the primary wrapper. It's safe for both x86 and x64.
        public static bool ReadProcessMemory(
            IntPtr hProcess,
            ulong lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            ref uint lpNumberOfBytesRead
        )
        {
            bool ok = ReadProcessMemory(
                hProcess,
                new IntPtr((long)lpBaseAddress),
                lpBuffer,
                (UIntPtr)nSize,
                out UIntPtr bytesRead
            );

            lpNumberOfBytesRead = (uint)bytesRead;
            return ok;
        }


        // address -> IntPtr helper
        private static IntPtr AddrToIntPtr(ulong address)
        {
            return new IntPtr(unchecked((long)address));
        }

        private static bool ReadProcessMemoryW(IntPtr hProcess, ulong address, byte[] buffer, out uint bytesRead)
        {
            bool ok = ReadProcessMemory(hProcess, new IntPtr(unchecked((long)address)), buffer, (UIntPtr)buffer.Length, out UIntPtr read64);
            bytesRead = (uint)read64;
            return ok;
        }


        // wrapper: read with explicit length (UIntPtr)
        private static bool ReadProcessMemoryW(IntPtr hProcess, ulong address, byte[] buffer, UIntPtr size, out uint bytesRead)
        {
            bool ok = ReadProcessMemory(hProcess, AddrToIntPtr(address), buffer, size, out UIntPtr read64);
            bytesRead = (uint)read64;
            return ok;
        }
        public enum ProcessAccess
        {
            /// <summary>Enables usage of the process handle in the TerminateProcess function to terminate the process.</summary>
            Terminate = 0x1,
            /// <summary>Enables usage of the process handle in the CreateRemoteThread function to create a thread in the process.</summary>
            CreateThread = 0x2,
            /// <summary>Enables usage of the process handle in the VirtualProtectEx and WriteProcessMemory functions to modify the virtual memory of the process.</summary>
            VMOperation = 0x8,
            /// <summary>Enables usage of the process handle in the ReadProcessMemory function to' read from the virtual memory of the process.</summary>
            VMRead = 0x10,
            /// <summary>Enables usage of the process handle in the WriteProcessMemory function to write to the virtual memory of the process.</summary>
            VMWrite = 0x20,
            /// <summary>Enables usage of the process handle as either the source or target process in the DuplicateHandle function to duplicate a handle.</summary>
            DuplicateHandle = 0x40,
            /// <summary>Enables usage of the process handle in the SetPriorityClass function to set the priority class of the process.</summary>
            SetInformation = 0x200,
            /// <summary>Enables usage of the process handle in the GetExitCodeProcess and GetPriorityClass functions to read information from the process object.</summary>
            QueryInformation = 0x400,
            /// <summary>Enables usage of the process handle in any of the wait functions to wait for the process to terminate.</summary>
            Synchronize = 0x100000,
            /// <summary>Specifies all possible access flags for the process object.</summary>
            AllAccess = CreateThread | DuplicateHandle | QueryInformation | SetInformation | Terminate | VMOperation | VMRead | VMWrite | Synchronize
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public ushort wProcessorArchitecture;
            public ushort wReserved;
            public uint dwPageSize;
            public IntPtr lpMinimumApplicationAddress;
            public IntPtr lpMaximumApplicationAddress;
            public UIntPtr dwActiveProcessorMask;
            public uint dwNumberOfProcessors;
            public uint dwProcessorType;
            public uint dwAllocationGranularity;
            public ushort wProcessorLevel;
            public ushort wProcessorRevision;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [DllImport("kernel32")]
        public static extern void GetSystemInfo(ref SYSTEM_INFO pSI);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);


        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, int bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint dwFlags, System.Text.StringBuilder lpExeName, ref uint lpdwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint PROCESS_TERMINATE = 0x0001;
        private const uint PROCESS_CREATE_THREAD = 0x0002;
        private const uint PROCESS_SET_SESSIONID = 0x0004;
        private const uint PROCESS_VM_OPERATION = 0x0008;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_VM_WRITE = 0x0020;
        private const uint PROCESS_DUP_HANDLE = 0x0040;
        private const uint PROCESS_CREATE_PROCESS = 0x0080;
        private const uint PROCESS_SET_QUOTA = 0x0100;
        private const uint PROCESS_SET_INFORMATION = 0x0200;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;

        // Memory state constants
        public const uint MEM_COMMIT = 0x1000;
        public const uint MEM_PRIVATE = 0x20000;
        public const uint PAGE_NOACCESS = 0x01;
        public const uint PAGE_GUARD = 0x100;
        public const uint PAGE_EXECUTE = 0x10;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_EXECUTE_WRITECOPY = 0x80;

        //inner enum used only internally
        [Flags]
        private enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            Inherit = 0x80000000,
            All = HeapList | Process | Thread | Module | Module32
        }
        //inner struct used only internally
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct PROCESSENTRY32
        {
            private const int MAX_PATH = 260;
            internal uint dwSize;
            internal uint cntUsage;
            internal uint th32ProcessID;
            internal IntPtr th32DefaultHeapID;
            internal uint th32ModuleID;
            internal uint cntThreads;
            internal uint th32ParentProcessID;
            internal int pcPriClassBase;
            internal uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            internal string szExeFile;
        }

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr CreateToolhelp32Snapshot([In] uint dwFlags, [In] uint th32ProcessID);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool Process32First([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool Process32Next([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        // ---- Module enumeration via Toolhelp (works for both 32-bit and 64-bit targets) ----
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct MODULEENTRY32
        {
            internal uint  dwSize;
            internal uint  th32ModuleID;
            internal uint  th32ProcessID;
            internal uint  GlblcntUsage;
            internal uint  ProccntUsage;
            internal IntPtr modBaseAddr;
            internal uint  modBaseSize;
            internal IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            internal string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            internal string szExePath;
        }

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool Module32First([In] IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool Module32Next([In] IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        // ---- EnumProcessModulesEx: LIST_MODULES_ALL enumerates both 32 and 64 bit modules ----
        private const uint LIST_MODULES_ALL = 0x03;

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool EnumProcessModulesEx(
            IntPtr hProcess, [Out] IntPtr[] lphModule, uint cb,
            out uint lpcbNeeded, uint dwFilterFlag);

        [DllImport("psapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern uint GetModuleBaseName(
            IntPtr hProcess, IntPtr hModule,
            System.Text.StringBuilder lpBaseName, uint nSize);

        // ---- WOW64 detection (32-bit process running on 64-bit OS) ----
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process(IntPtr hProcess, out bool Wow64Process);

        // ---- NtQueryInformationProcess overload for class 26 (ProcessWow64Information)
        //      which returns the 32-bit PEB address of a WOW64 process as a single pointer ----
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationProcess(
            IntPtr processHandle, int processInformationClass,
            ref IntPtr processInformation, uint processInformationLength,
            out int returnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationProcess(IntPtr processHandle,
           int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, uint processInformationLength,
           out int returnLength);

        // Thread Access Rights
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetThreadContext")]
        private static extern bool GetThreadContext64(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetThreadContext")]
        private static extern bool GetThreadContext32(IntPtr hThread, ref CONTEXT32 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;
            public uint ContextFlags;
            public uint MxCsr;
            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;
            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;
            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;
            // ... vector registers omitted for brevity/relevance (we only need RIP) ...
            // Sufficient size buffer is needed if ContextFlags requests more.
            // But for simple Integer/Control, this matches standard layout until vector regs.
            // To be safe, we can add padding/dummy storage if GetThreadContext writes more.
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT32
        {
            public uint ContextFlags;
            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;
            public FLOATING_SAVE_AREA FloatSave;
            public uint SegGs;
            public uint SegFs;
            public uint SegEs;
            public uint SegDs;
            public uint Edi;
            public uint Esi;
            public uint Ebx;
            public uint Edx;
            public uint Ecx;
            public uint Eax;
            public uint Ebp;
            public uint Eip;
            public uint SegCs;
            public uint EFlags;
            public uint SegSs;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FLOATING_SAVE_AREA
        {
            public uint ControlWord;
            public uint StatusWord;
            public uint TagWord;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;
            public uint Cr0NpxState;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }


        #region New CLI Methods

        /// <summary>
        /// Performs a process dump from the command line, without UI interaction.
        /// </summary>
        /// <param name="processId">The ID of the process to dump.</param>
        /// <param name="outputDirectory">The root directory for the dump files.</param>
        /// <returns>A string indicating the result of the dump operation.</returns>
        public string DumpProcessByIdCli(uint processId, string outputDirectory, bool restoreFilename = true)
        {
            if (string.IsNullOrWhiteSpace(outputDirectory))
            {
                return "Error: Output directory must be provided.";
            }

            DUMP_DIRECTORIES ddirs = new() { root = outputDirectory };
            if (!CreateDirectoriesCli(ref ddirs))
            {
                return "Error: Could not create or access the output directory. Please check permissions and path.";
            }

            return DumpProcessLogic(processId, ddirs, true /* dumpNative */, restoreFilename);
        }

        /// <summary>
        /// Dumps a process into directories CreateDirectoriesCli prepared (the DLL
        /// export's entry). Returns the summary of what was dumped.
        /// </summary>
        public string DumpProcess(uint processId, DUMP_DIRECTORIES ddirs, bool dumpNative, bool restoreFilename)
        {
            return DumpProcessLogic(processId, ddirs, dumpNative, restoreFilename);
        }

        /// <summary>
        /// Creates dump directories without showing any UI dialogs. For CLI use.
        /// </summary>
        /// <param name="dpmdirs">The struct containing directory paths.</param>
        /// <returns>True if successful, false otherwise.</returns>
        public bool CreateDirectoriesCli(ref DUMP_DIRECTORIES dpmdirs)
        {
            SetDirectoriesPath(ref dpmdirs);
            try
            {
                Directory.CreateDirectory(dpmdirs.dumps);
                Directory.CreateDirectory(dpmdirs.nativedirname);
                Directory.CreateDirectory(dpmdirs.sysdirname);
                Directory.CreateDirectory(dpmdirs.unknowndirname);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Error] Failed to create directories: {ex.Message}");
                return false;
            }
        }
        #endregion

        private bool CheckAdvancedPEStructure(IntPtr hProcess, ulong baseAddress, int peOffset)
        {
            try
            {
                // Read PE headers for validation
                byte[] peHeaders = new byte[256];
                uint bytesRead = 0;

                // Read the PE header structure
                try
                {
                    if (ReadProcessMemory(hProcess, baseAddress + (uint)peOffset, peHeaders, 256, ref bytesRead) && bytesRead >= 24)
                    {
                        // Validate PE signature (already checked, but double-check)
                        if (peHeaders[0] != 0x50 || peHeaders[1] != 0x45) // "PE"
                            return false;

                        // Read COFF Header (IMAGE_FILE_HEADER)
                        short machine = BitConverter.ToInt16(peHeaders, 4);
                        short numberOfSections = BitConverter.ToInt16(peHeaders, 6);
                        int timeDateStamp = BitConverter.ToInt32(peHeaders, 8);
                        short sizeOfOptionalHeader = BitConverter.ToInt16(peHeaders, 20);
                        short characteristics = BitConverter.ToInt16(peHeaders, 22);

                        // Validate machine type (x86, x64, ARM, etc.)
                        if (!IsValidMachineType((ushort)machine))
                            return false;

                        // Validate section count (reasonable range)
                        if (numberOfSections <= 0 || numberOfSections > 96)
                            return false;

                        // Validate optional header magic and size
                        ushort optHeaderMagic = BitConverter.ToUInt16(peHeaders, 24);
                        if (optHeaderMagic == 0x10B) // PE32
                        {
                            if (sizeOfOptionalHeader < 224) return false;
                        }
                        else if (optHeaderMagic == 0x20B) // PE32+
                        {
                            if (sizeOfOptionalHeader < 240) return false;
                        }
                        else
                        {
                            return false; // Unknown magic
                        }

                        // Check if it's an executable image
                        if ((characteristics & 0x0002) == 0) // IMAGE_FILE_EXECUTABLE_IMAGE not set
                        {
                            // Still might be valid if it's a DLL
                            if ((characteristics & 0x2000) == 0) // IMAGE_FILE_DLL not set either
                                return false;
                        }

                        return true;
                    }
                }
                catch (System.ComponentModel.Win32Exception)
                {
                }
                return false;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                return false;
            }
            catch
            {
                return false;
            }
        }

        private bool IsValidMachineType(ushort machine)
        {
            switch (machine)
            {
                case 0x014c: // x86
                case 0x8664: // x64
                case 0x01c0: // ARM
                case 0xaa64: // ARM64
                case 0x0200: // IA64
                case 0x01c4: // ARMNT
                    return true;
                default:
                    return false;
            }
        }


        /// <summary>
        /// Gets the full on-disk path of a process using QueryFullProcessImageName.
        /// Works correctly regardless of host/target bitness mismatch.
        /// </summary>
        private string GetProcessImagePath(int processId)
        {
            const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
            IntPtr hProcess = IntPtr.Zero;
            try
            {
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, (uint)processId);
                if (hProcess == IntPtr.Zero)
                    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, (uint)processId);
                if (hProcess == IntPtr.Zero) return null;

                var sb = new System.Text.StringBuilder(1024);
                uint size = (uint)sb.Capacity;
                return QueryFullProcessImageName(hProcess, 0, sb, ref size) ? sb.ToString() : null;
            }
            catch { return null; }
            finally
            {
                if (hProcess != IntPtr.Zero)
                    try { CloseHandle(hProcess); } catch { }
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            public long Luid;
            public int Attributes;
        }

        private const int SE_PRIVILEGE_ENABLED = 0x00000002;
        private const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        private const int TOKEN_QUERY = 0x00000008;

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, ref int tokenhandle);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int LookupPrivilegeValue(string lpsystemname, string lpname, ref long lpLuid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int AdjustTokenPrivileges(int tokenhandle, int disableprivs, ref TOKEN_PRIVILEGES Newstate, int bufferlength, int PreivousState, int Returnlength);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int GetSecurityInfo(int HANDLE, int SE_OBJECT_TYPE, int SECURITY_INFORMATION, int psidOwner, int psidGroup, out IntPtr pDACL, IntPtr pSACL, out IntPtr pSecurityDescriptor);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int SetSecurityInfo(int HANDLE, int SE_OBJECT_TYPE, int SECURITY_INFORMATION, int psidOwner, int psidGroup, IntPtr pDACL, IntPtr pSACL);

        public void EnableDebuggerPrivileges()
        {
            try
            {
                int token = 0;
                TOKEN_PRIVILEGES tp = new()
                {
                    PrivilegeCount = 1,
                    Luid = 0,
                    Attributes = SE_PRIVILEGE_ENABLED
                };

                // We just assume this works
                if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref token) == 0)
                    return;

                if (LookupPrivilegeValue(null, "SeDebugPrivilege", ref tp.Luid) == 0)
                    return;

                if (AdjustTokenPrivileges(token, 0, ref tp, Marshal.SizeOf(tp), 0, 0) == 0)
                    return;
            }
            catch
            {
            }
        }


        public int RVA2Offset(byte[] input, int rva)
        {
            // Minimum size check for DOS header (0x3C) and PE header offset (4 bytes)
            if (input == null || input.Length < 0x3C + 4) return -1;

            int PEOffset = BitConverter.ToInt32(input, 0x3C);
            // Basic sanity check for PEOffset
            if (PEOffset < 0 || PEOffset >= input.Length) return -1;

            // Minimum size check for COFF header (0x06) and NumberOfSections (2 bytes)
            if (input.Length < PEOffset + 0x06 + 2) return -1;
            int nrofsection = BitConverter.ToInt16(input, PEOffset + 0x06);
            // Sanity check for number of sections
            if (nrofsection <= 0 || nrofsection > 96) return -1; // Max 96 sections is a common heuristic

            // Get SizeOfOptionalHeader to correctly calculate section table offset
            // This works for both PE32 (32-bit) and PE32+ (64-bit)
            if (input.Length < PEOffset + 0x14 + 2) return -1;
            short sizeOfOptionalHeader = BitConverter.ToInt16(input, PEOffset + 0x14);

            // Section table starts after: PE signature (4) + COFF header (20) + Optional header
            int sectionTableStartOffset = PEOffset + 4 + 20 + sizeOfOptionalHeader;

            for (int i = 0; i < nrofsection; i++)
            {
                // Each IMAGE_SECTION_HEADER is 0x28 bytes long
                int sectionHeaderOffset = sectionTableStartOffset + (0x28 * i);

                // Ensure there's enough room for the current section header (40 bytes)
                if (input.Length < sectionHeaderOffset + 0x28) return -1;

                // VirtualAddress is at offset 0x0C from section header start (4 bytes)
                int virtualAddress = BitConverter.ToInt32(input, sectionHeaderOffset + 0x0C);
                // VirtualSize is at offset 0x08 from section header start (4 bytes)
                int fvirtualsize = BitConverter.ToInt32(input, sectionHeaderOffset + 0x08);
                // SizeOfRawData is at offset 0x10 from section header start (4 bytes)
                int frawsize = BitConverter.ToInt32(input, sectionHeaderOffset + 0x10);
                // PointerToRawData is at offset 0x14 from section header start (4 bytes)
                int frawAddress = BitConverter.ToInt32(input, sectionHeaderOffset + 0x14);

                // Use the larger of VirtualSize or SizeOfRawData for bounds checking
                // This handles sections where VirtualSize is 0 in rebuilt sections.
                int effectiveSize = Math.Max(fvirtualsize, frawsize);
                if (effectiveSize <= 0) effectiveSize = frawsize > 0 ? frawsize : fvirtualsize;

                if ((virtualAddress <= rva) && (virtualAddress + effectiveSize >= rva))
                    return frawAddress + (rva - virtualAddress);
            }

            return -1;
        }

        public int Offset2RVA(byte[] input, int offset)
        {
            if (input == null || input.Length < 0x3C + 4) return -1;

            int PEOffset = BitConverter.ToInt32(input, 0x3C);
            if (PEOffset < 0 || PEOffset >= input.Length) return -1;

            if (input.Length < PEOffset + 0x06 + 2) return -1;
            int nrofsection = BitConverter.ToInt16(input, PEOffset + 0x06);
            if (nrofsection <= 0 || nrofsection > 96) return -1;

            // Assuming a standard 32-bit PE header structure, 0xF8 is a common offset
            // to the start of the section table after the PE signature, COFF header, and optional header.
            int sectionTableStartOffset = PEOffset + 0xF8;

            for (int i = 0; i < nrofsection; i++)
            {
                int sectionHeaderOffset = sectionTableStartOffset + (0x28 * i);

                if (input.Length < sectionHeaderOffset + 0x28) return -1;

                int virtualAddress = BitConverter.ToInt32(input, sectionHeaderOffset + 0x0C); // VirtualAddress
                // SizeOfRawData is at offset 0x10 from section header start (4 bytes)
                int frawsize = BitConverter.ToInt32(input, sectionHeaderOffset + 0x10);
                // PointerToRawData is at offset 0x14 from section header start (4 bytes)
                int frawAddress = BitConverter.ToInt32(input, sectionHeaderOffset + 0x14);

                if ((frawAddress <= offset) && (frawAddress + frawsize >= offset))
                    return virtualAddress + (offset - frawAddress);
            }

            return -1;
        }

        public unsafe struct image_section_header
        {
            public fixed byte name[8];
            public int virtual_size;
            public int virtual_address;
            public int size_of_raw_data;
            public int pointer_to_raw_data;
            public int pointer_to_relocations;
            public int pointer_to_linenumbers;
            public short number_of_relocations;
            public short number_of_linenumbers;
            public int characteristics;
        };

        public struct IMAGE_FILE_HEADER
        {
            public short Machine;
            public short NumberOfSections;
            public int TimeDateStamp;
            public int PointerToSymbolTable;
            public int NumberOfSymbols;
            public short SizeOfOptionalHeader;
            public short Characteristics;
        }

        private int ReadInt32Safe(byte[] buffer, int offset, int defaultValue = -1)
        {
            if (buffer == null || offset < 0 || offset + 4 > buffer.Length)
            {
                return defaultValue;
            }
            return BitConverter.ToInt32(buffer, offset);
        }

        private short ReadInt16Safe(byte[] buffer, int offset, short defaultValue = -1)
        {
            if (buffer == null || offset < 0 || offset + 2 > buffer.Length)
            {
                return defaultValue;
            }
            return BitConverter.ToInt16(buffer, offset);
        }

        public bool FixImportandEntryPoint(long dumpVA, byte[] Dump)
        {
            if (Dump == null || Dump.Length < 0x40) return false;

            int PEOffset = ReadInt32Safe(Dump, 0x3C);
            if (PEOffset < 0 || PEOffset >= Dump.Length - 0x100) return false;

            // Detect architecture
            ushort magic = BitConverter.ToUInt16(Dump, PEOffset + 24);
            bool isPE64 = (magic == 0x20B);

            int ImportDirectoryRva = ReadInt32Safe(Dump, PEOffset + (isPE64 ? 0x090 : 0x080));
            int impdiroffset = RVA2Offset(Dump, ImportDirectoryRva);
            if (impdiroffset == -1) return false;

            byte[] mscoreeAscii = { 0x6D, 0x73, 0x63, 0x6F, 0x72, 0x65, 0x65, 0x2E, 0x64, 0x6C, 0x6C, 0x00 };
            byte[] CorExeMain = { 0x5F, 0x43, 0x6F, 0x72, 0x45, 0x78, 0x65, 0x4D, 0x61, 0x69, 0x6E, 0x00 };
            byte[] CorDllMain = { 0x5F, 0x43, 0x6F, 0x72, 0x44, 0x6C, 0x6C, 0x4D, 0x61, 0x69, 0x6E, 0x00 };
            int ThunkToFix = 0;
            long ThunkData = 0;
            int current = 0;

            while (impdiroffset + current + 20 <= Dump.Length)
            {
                int NameRVA = ReadInt32Safe(Dump, impdiroffset + current + 12);
                if (NameRVA <= 0) break;

                int NameOffset = RVA2Offset(Dump, NameRVA);
                if (NameOffset == -1) { current += 20; continue; }

                bool ismscoree = true;
                for (int i = 0; i < mscoreeAscii.Length; i++)
                {
                    if (NameOffset + i >= Dump.Length || Dump[NameOffset + i] != mscoreeAscii[i])
                    {
                        ismscoree = false;
                        break;
                    }
                }

                if (ismscoree)
                {
                    int OriginalFirstThunk = ReadInt32Safe(Dump, impdiroffset + current);
                    int OriginalFirstThunkfo = RVA2Offset(Dump, OriginalFirstThunk);
                    if (OriginalFirstThunkfo == -1) { current += 20; continue; }

                    if (isPE64)
                        ThunkData = BitConverter.ToInt64(Dump, OriginalFirstThunkfo);
                    else
                        ThunkData = BitConverter.ToInt32(Dump, OriginalFirstThunkfo);

                    int ThunkDatafo = RVA2Offset(Dump, (int)(ThunkData & 0xFFFFFFFF));
                    if (ThunkDatafo == -1) { current += 20; continue; }

                    ismscoree = true;
                    for (int i = 0; i < CorExeMain.Length; i++)
                    {
                        if (ThunkDatafo + 2 + i >= Dump.Length || (Dump[ThunkDatafo + 2 + i] != CorExeMain[i] && Dump[ThunkDatafo + 2 + i] != CorDllMain[i]))
                        {
                            ismscoree = false;
                            break;
                        }
                    }

                    if (ismscoree)
                    {
                        ThunkToFix = ReadInt32Safe(Dump, impdiroffset + current + 16);
                        break;
                    }
                }
                current += 20;
            }

            if (ThunkToFix <= 0 || ThunkData == 0) return false;

            int ThunkToFixfo = RVA2Offset(Dump, ThunkToFix);
            if (ThunkToFixfo == -1) return false;

            using var ms = new MemoryStream(Dump);
            BinaryWriter writer = new(ms);

            long currentThunkValue = isPE64 ? BitConverter.ToInt64(Dump, ThunkToFixfo) : BitConverter.ToInt32(Dump, ThunkToFixfo);
            if (currentThunkValue <= 0 || RVA2Offset(Dump, (int)(currentThunkValue & 0xFFFFFFFF)) == -1)
            {
                ms.Position = ThunkToFixfo;
                if (isPE64)
                    writer.Write((long)ThunkData);
                else
                    writer.Write((int)ThunkData);
            }

            int EntryPointOffset = PEOffset + 0x028;
            int EntryPoint = ReadInt32Safe(Dump, EntryPointOffset);

            if (EntryPoint <= 0 || RVA2Offset(Dump, EntryPoint) == -1)
            {
                long realThunkAddress = dumpVA + ThunkToFix;
                byte[] ThunkToFixbytes = BitConverter.GetBytes(isPE64 ? (ulong)realThunkAddress : (ulong)(uint)realThunkAddress);

                if (isPE64)
                {
                    // For x64, we search for FF 25 [Rel32] pointing to the thunk
                    for (int i = 0; i < Dump.Length - 6; i++)
                    {
                        if (Dump[i] == 0xFF && Dump[i + 1] == 0x25)
                        {
                            int rel32 = BitConverter.ToInt32(Dump, i + 2);
                            long targetVA = (long)dumpVA + i + 6 + rel32;
                            if (targetVA == realThunkAddress)
                            {
                                int EntrPointRVA = Offset2RVA(Dump, i);
                                if (EntrPointRVA != -1)
                                {
                                    ms.Position = EntryPointOffset;
                                    writer.Write(EntrPointRVA);
                                    break;
                                }
                            }
                        }
                    }
                }
                else
                {
                    byte[] pattern = BitConverter.GetBytes((uint)realThunkAddress);
                    for (int i = 0; i < Dump.Length - 6; i++)
                    {
                        if (Dump[i] == 0xFF && Dump[i + 1] == 0x25 &&
                            Dump[i + 2] == pattern[0] && Dump[i + 3] == pattern[1] &&
                            Dump[i + 4] == pattern[2] && Dump[i + 5] == pattern[3])
                        {
                            int EntrPointRVA = Offset2RVA(Dump, i);
                            if (EntrPointRVA != -1)
                            {
                                ms.Position = EntryPointOffset;
                                writer.Write(EntrPointRVA);
                                break;
                            }
                        }
                    }
                }
            }

            return true;
        }

        public struct DUMP_DIRECTORIES
        {
            public string root;
            public string dumps;
            public string nativedirname;
            public string sysdirname;
            public string unknowndirname;
        }

        public void SetDirectoriesPath(ref DUMP_DIRECTORIES dpmdirs)
        {
            if (string.IsNullOrEmpty(dpmdirs.root)) dpmdirs.root = Path.Combine("C:\\", "Dumps");
            
            dpmdirs.dumps = dpmdirs.root;
            dpmdirs.nativedirname = Path.Combine(dpmdirs.dumps, "Native");
            dpmdirs.sysdirname = Path.Combine(dpmdirs.dumps, "System");
            dpmdirs.unknowndirname = Path.Combine(dpmdirs.dumps, "UnknownName");
        }


        static ulong PtrToULong(IntPtr ip)
        {
            if (IntPtr.Size == 8)
            {
                long v = ip.ToInt64();
                return BitConverter.ToUInt64(BitConverter.GetBytes(v), 0);
            }
            else
            {
                int v = ip.ToInt32();
                return BitConverter.ToUInt32(BitConverter.GetBytes(v), 0);
            }
        }

        private unsafe string DumpProcessLogic(uint processId, DUMP_DIRECTORIES ddirs, bool dumpNative, bool restoreFilename)
        {
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 0, processId);
            List<string> sessionDumpedFiles = new List<string>();

            // The Ultimate Heuristic: Ask the Windows kernel if this process dynamically booted the CLR!
            // Defeats FakeNet-NG (fake PE header) and Enigma (stripped PE header + manually mapped CLR).
            bool isProcessDynamicallyManaged = false;
            Console.WriteLine("[INFO] Checking if process is dynamically managed (CLR)...");
            try
            {
                // Raw COM (CorPublishNative): NativeAOT has no built-in COM interop.
                bool? managed = CorPublishNative.IsManaged(processId);
                if (managed.HasValue)
                    isProcessDynamicallyManaged = managed.Value;
                else
                    Console.WriteLine("[DEBUG] ICorPublish unavailable (no CLR debugging services registered). Falling back to kernel/module inspection...");
            }
            catch (Exception ex) 
            { 
                Console.WriteLine($"[DEBUG] ICorPublish check failed: {ex.Message}. Falling back to kernel/module inspection..."); 
            }

            // Kernel/Module Inspection Fallback
            if (!isProcessDynamicallyManaged)
            {
                try
                {
                    using (var proc = Process.GetProcessById((int)processId))
                    {
                        foreach (ProcessModule mod in proc.Modules)
                        {
                            string modName = mod.ModuleName.ToLower();
                            if (modName == "clr.dll" || modName == "mscorlib.dll" || modName == "coreclr.dll" || modName == "mscoree.dll")
                            {
                                isProcessDynamicallyManaged = true;
                                Console.WriteLine($"[INFO] Managed status: True (Detected {mod.ModuleName} in process modules)");
                                break;
                            }
                        }
                    }
                }
                catch (Exception modEx) { Console.WriteLine($"[DEBUG] Module inspection failed: {modEx.Message}"); }
            }

            Console.WriteLine($"[INFO] Managed status: {isProcessDynamicallyManaged}");

            if (hProcess == IntPtr.Zero)
            {
                GetSecurityInfo((int)Process.GetCurrentProcess().Handle, 6, 4, 0, 0, out IntPtr pDACL, IntPtr.Zero, out IntPtr pSecDesc);
                hProcess = OpenProcess(0x40000, 0, processId);
                SetSecurityInfo((int)hProcess, 6, 4 | 0x20000000, 0, 0, pDACL, IntPtr.Zero);
                CloseHandle(hProcess);
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 0, processId);
            }

            if (hProcess == IntPtr.Zero)
            {
                return "Failed to open selected process!";
            }

            Console.WriteLine($"[INFO] Starting memory scan for PID {processId}...");

            try
            {
                ulong minaddress = 0;
                ulong maxaddress = 0;
                ulong pagesize = 0x1000UL;
                try
                {
                    SYSTEM_INFO pSI = new();
                    GetSystemInfo(ref pSI);

                    minaddress = PtrToULong(pSI.lpMinimumApplicationAddress);
                    maxaddress = PtrToULong(pSI.lpMaximumApplicationAddress);
                    pagesize = pSI.dwPageSize;
                }
                catch
                {
                }

                int CurrentCount = 1;

                bool isok;
                int pagesizeInt = (pagesize > int.MaxValue) ? 0x1000 : (int)pagesize;
                byte[] onepage = new byte[pagesizeInt];
                uint BytesRead = 0;
                byte[] infokeep = new byte[8];

                // --- 64-bit compatible iteration ---
                ulong currentAddress = minaddress;
                ulong totalShellcodeBytes = 0;
                MEMORY_BASIC_INFORMATION mbi;
                uint mbiSize = (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

                Console.WriteLine($"[INFO] Memory scan range: 0x{currentAddress:X16} - 0x{maxaddress:X16}");

                while (currentAddress < maxaddress && VirtualQueryEx(hProcess, AddrToIntPtr(currentAddress), out mbi, mbiSize) != 0)
                {
                    // Log progress more frequently for x64 (every 1GB)
                    if (currentAddress % 0x40000000 == 0) 
                        Console.WriteLine($"[INFO] Scanning memory... Current Address: 0x{currentAddress:X16}");
                    // =================== FIX START ===================
                    // We are interested in committed memory that is not guarded and is accessible.
                    // The original check was flawed because it didn't use bitwise operations,
                    // which could lead to reading invalid memory and causing the access violation.
                    bool isMemoryReadable = (mbi.State == MEM_COMMIT) &&
                                            ((mbi.Protect & PAGE_GUARD) == 0) &&
                                            ((mbi.Protect & PAGE_NOACCESS) == 0);

                    if (isMemoryReadable)
                    {
                        bool regionHadPe = false;
                        ulong regionBase = PtrToULong(mbi.BaseAddress);
                        ulong regionSize = PtrToULong(mbi.RegionSize);
                        ulong regionEnd = regionBase + regionSize;

                        // Now scan this valid memory region page by page
                        for (ulong j = regionBase; j < regionEnd; j += pagesize)
                        {
                            isok = ReadProcessMemoryW(hProcess, j, onepage, out BytesRead);
                            if (!isok || BytesRead == 0)
                                continue;

                            if (isok)
                            {
                                // FIXED: Multiple safety checks to prevent index out of range
                                // Ensure we have at least 2 bytes and don't exceed array bounds
                                if (BytesRead < 2) continue;

                                // Ensure BytesRead doesn't exceed the actual array size
                                int safeByteCount = Math.Min((int)BytesRead, onepage.Length);
                                if (safeByteCount < 2) continue;

                                for (int k = 0; k < safeByteCount - 1; k++)
                                {
                                    // Additional safety check before array access
                                    if (k >= onepage.Length - 1) break;

                                    // check MZ signature in buffer - now safe with multiple bounds checks
                                    if (onepage[k] == 0x4D && onepage[k + 1] == 0x5A)
                                    {
                                        // Read PE header offset (4 bytes) at j + k + 0x03C
                                        ulong peOffsetAddr = j + (ulong)k + 0x03CUL;
                                        if (!ReadProcessMemoryW(hProcess, peOffsetAddr, infokeep, (UIntPtr)4, out BytesRead))
                                            continue;

                                        int PEOffset = BitConverter.ToInt32(infokeep, 0);
                                        if (PEOffset <= 0 || PEOffset > 0x1000)
                                            continue;

                                        // Verify 'PE' signature before logging
                                        byte[] peSig = new byte[4];
                                        if (ReadProcessMemoryW(hProcess, j + (ulong)k + (ulong)PEOffset, peSig, (UIntPtr)4, out BytesRead) && 
                                            peSig[0] == 0x50 && peSig[1] == 0x45)
                                        {
                                            Console.WriteLine($"[DEBUG] Found valid PE header at 0x{(j + (ulong)k):X16}");
                                        }
                                        else continue;

                                        // ensure PEOffset falls within our local buffer first, else read from remote
                                        long localPeIndex = (long)k + PEOffset;
                                        bool localOrRemotePeSigOk = false;
                                        if (localPeIndex >= 0 && (localPeIndex + 4) <= safeByteCount)
                                        {
                                            localOrRemotePeSigOk =
                                                onepage[localPeIndex] == 0x50 &&
                                                onepage[localPeIndex + 1] == 0x45 &&
                                                onepage[localPeIndex + 2] == 0x00 &&
                                                onepage[localPeIndex + 3] == 0x00;
                                        }
                                        else
                                        {
                                            byte[] remotePeSig = new byte[4];
                                            if (ReadProcessMemoryW(hProcess, j + (ulong)k + (ulong)PEOffset, remotePeSig, (UIntPtr)4, out BytesRead) && BytesRead == 4)
                                            {
                                                localOrRemotePeSigOk =
                                                    remotePeSig[0] == 0x50 &&
                                                    remotePeSig[1] == 0x45 &&
                                                    remotePeSig[2] == 0x00 &&
                                                    remotePeSig[3] == 0x00;
                                            }
                                        }

                                        if (localOrRemotePeSigOk)
                                        {
                                            if (PEOffset > 0)
                                            {
                                                bool isNetAssembly = false;

                                                // --- SAFELY obtain e_lfanew (PE header offset) ---
                                                int e_lfanew = -1;
                                                // try read from local buffer if available
                                                if (k + 0x3C + 4 <= safeByteCount)
                                                {
                                                    e_lfanew = BitConverter.ToInt32(onepage, k + 0x3C);
                                                }
                                                else
                                                {
                                                    // fallback: read 4 bytes from remote process at (j + k + 0x3C)
                                                    if (!ReadProcessMemoryW(hProcess, j + (ulong)k + 0x03CUL, infokeep, (UIntPtr)4, out BytesRead))
                                                        continue;
                                                    e_lfanew = BitConverter.ToInt32(infokeep, 0);
                                                }

                                                if (e_lfanew <= 0)
                                                    continue;

                                                // compute local index of PE signature relative to onepage
                                                long peSigLocalIndex = (long)k + e_lfanew;

                                                // verify 'PE\0\0' either in local buffer or by remote read
                                                bool peSigOk = false;
                                                if (peSigLocalIndex >= 0 && (peSigLocalIndex + 4) <= safeByteCount)
                                                {
                                                    // signature is inside current local buffer
                                                    if (onepage[peSigLocalIndex] == 0x50 && onepage[peSigLocalIndex + 1] == 0x45
                                                        && onepage[peSigLocalIndex + 2] == 0x00 && onepage[peSigLocalIndex + 3] == 0x00)
                                                        peSigOk = true;
                                                }
                                                else
                                                {
                                                    // signature not fully in local page: read 4 bytes from remote to confirm
                                                    if (ReadProcessMemoryW(hProcess, j + (ulong)k + (ulong)e_lfanew, infokeep, (UIntPtr)4, out BytesRead))
                                                    {
                                                        if (BytesRead == 4 && infokeep[0] == 0x50 && infokeep[1] == 0x45 && infokeep[2] == 0x00 && infokeep[3] == 0x00)
                                                            peSigOk = true;
                                                    }
                                                }

                                                if (!peSigOk)
                                                    continue;

                                                // --- SAFELY read NumberOfSections and SizeOfOptionalHeader ---
                                                int numberOfSections = 0;
                                                short sizeOfOptionalHeader = 0;

                                                // NumberOfSections is at offset +6 from PE signature (i.e. e_lfanew + 6)
                                                if (peSigLocalIndex >= 0 && (peSigLocalIndex + 8) <= safeByteCount)
                                                {
                                                    numberOfSections = BitConverter.ToInt16(onepage, (int)peSigLocalIndex + 6);
                                                }
                                                else
                                                {
                                                    if (!ReadProcessMemoryW(hProcess, j + (ulong)k + (ulong)e_lfanew + 6UL, infokeep, (UIntPtr)2, out BytesRead))
                                                        continue;
                                                    numberOfSections = BitConverter.ToInt16(infokeep, 0);
                                                }

                                                // SizeOfOptionalHeader is at offset 20 from PE signature (e_lfanew + 20)
                                                if (peSigLocalIndex >= 0 && (peSigLocalIndex + 22) <= safeByteCount)
                                                {
                                                    sizeOfOptionalHeader = BitConverter.ToInt16(onepage, (int)peSigLocalIndex + 20);
                                                }
                                                else
                                                {
                                                    if (!ReadProcessMemoryW(hProcess, j + (ulong)k + (ulong)e_lfanew + 20UL, infokeep, (UIntPtr)2, out BytesRead))
                                                        continue;
                                                    sizeOfOptionalHeader = BitConverter.ToInt16(infokeep, 0);
                                                }

                                                // sanity checks
                                                if (numberOfSections <= 0 || numberOfSections >= 100)
                                                    continue;

                                                // Restore CheckAdvancedPEStructure call to get isNetAssembly status
                                                isNetAssembly = false;
                                                try
                                                {
                                                    isNetAssembly = CheckAdvancedPEStructure(hProcess, (j + (ulong)k), e_lfanew);
                                                }
                                                catch { isNetAssembly = false; }

                                                // Determine architecture and correct Metadata offset
                                                ushort magic = 0;
                                                // Read Magic bytes (PE Signature + 24 bytes = offset 24 in NT header)
                                                if (ReadProcessMemoryW(hProcess, (j + (ulong)k + (ulong)e_lfanew + 24UL), infokeep, (UIntPtr)2, out BytesRead))
                                                    magic = BitConverter.ToUInt16(infokeep, 0);

                                                bool isPE64 = (magic == 0x20B);
                                                int metadataOffset = isPE64 ? 0x0F8 : 0x0E8;

                                                long NetMetadata = 0;
                                                // read 8 bytes at CLR metadata pointer
                                                ulong netMetaAddr = j + (ulong)k + (ulong)e_lfanew + (ulong)metadataOffset;
                                                if (ReadProcessMemoryW(hProcess, netMetaAddr, infokeep, (UIntPtr)8, out BytesRead))
                                                    NetMetadata = BitConverter.ToInt64(infokeep, 0);

                                                if (dumpNative || NetMetadata != 0 || isProcessDynamicallyManaged)
                                                {
                                                    // For VMP, we prefer a raw header capture without heavy fixups at the dump stage.
                                                    int peHeaderSize = Math.Max(pagesizeInt, e_lfanew + 0x400);
                                                    byte[] PeHeader = new byte[peHeaderSize];
                                                    if (!ReadProcessMemoryW(hProcess, j + (ulong)k, PeHeader, (UIntPtr)peHeaderSize, out BytesRead))
                                                        continue;

                                                    // Verify we have enough data
                                                    if (BytesRead < PEOffset + 0x100) continue;

                                                    int nrofsection = BitConverter.ToInt16(PeHeader, PEOffset + 0x06);

                                                    if (nrofsection > 0 && nrofsection < 100) // Sanity check for number of sections
                                                    {
                                                        string dumpdir = ddirs.dumps; // ALWAYS dump to the main directory

                                                        // Read section alignment values directly from memory to ensure accuracy
                                                        byte[] alignmentBytes = new byte[8];
                                                        if (!ReadProcessMemoryW(hProcess, j + (ulong)k + (ulong)PEOffset + 0x038, alignmentBytes, (UIntPtr)8, out BytesRead))
                                                            continue;

                                                        int sectionalignment = BitConverter.ToInt32(alignmentBytes, 0);
                                                        int filealignment = BitConverter.ToInt32(alignmentBytes, 4);
                                                        // Read SizeOfOptionalHeader directly from memory
                                                        byte[] optHeaderSizeBytes = new byte[2];
                                                        if (!ReadProcessMemoryW(hProcess, j + (ulong)k + (ulong)PEOffset + 0x014, optHeaderSizeBytes, (UIntPtr)2, out BytesRead))
                                                            continue;

                                                        short sizeofoptionalheader = BitConverter.ToInt16(optHeaderSizeBytes, 0);

                                                        bool IsDll = false;
                                                        if ((PeHeader[PEOffset + 0x017] & 32) != 0) IsDll = true;

                                                        image_section_header[] sections = new image_section_header[nrofsection];

                                                        // compute ptr as 64-bit address (base of section table)
                                                        ulong ptr = (ulong)j + (ulong)k + (ulong)PEOffset + (ulong)sizeofoptionalheader + 4UL + (ulong)Marshal.SizeOf<IMAGE_FILE_HEADER>();

                                                        for (int i = 0; i < nrofsection; i++)
                                                        {
                                                            byte[] datakeeper = new byte[Marshal.SizeOf<image_section_header>()];
                                                            if (!ReadProcessMemoryW(hProcess, ptr, datakeeper, (UIntPtr)datakeeper.Length, out BytesRead))
                                                                break;

                                                            fixed (byte* p = datakeeper)
                                                            {
                                                                sections[i] = Marshal.PtrToStructure<image_section_header>((IntPtr)p);
                                                            }

                                                            ptr += (ulong)Marshal.SizeOf<image_section_header>();
                                                        }

                                                        // --- ON-DISK SECTION TABLE (authoritative raw layout) ---
                                                        // Packers (Themida/VMP) scramble PointerToRawData/SizeOfRawData in
                                                        // memory (anti-dump). Recover the true raw layout from the on-disk
                                                        // image, then read section *content* from the process at the VAs.
                                                        image_section_header[] onDiskSections = null;
                                                        int onDiskNrofSections = 0;
                                                        int onDiskTotalRawSize = 0;
                                                        string imagePath = null;
                                                        try { imagePath = GetProcessImagePath((int)processId); } catch { }
                                                        if (!string.IsNullOrEmpty(imagePath) && File.Exists(imagePath))
                                                        {
                                                            try
                                                            {
                                                                byte[] diskBytes = File.ReadAllBytes(imagePath);
                                                                int diskLfanew = BitConverter.ToInt32(diskBytes, 0x3C);
                                                                int diskNs = BitConverter.ToInt16(diskBytes, diskLfanew + 6);
                                                                int diskOpt = BitConverter.ToInt16(diskBytes, diskLfanew + 20);
                                                                if (diskNs > 0 && diskNs < 100 &&
                                                                    (diskLfanew + 24 + diskOpt + diskNs * 40) <= diskBytes.Length)
                                                                {
                                                                    onDiskSections = new image_section_header[diskNs];
                                                                    int dsecOff = diskLfanew + 24 + diskOpt;
                                                                    for (int di = 0; di < diskNs; di++)
                                                                    {
                                                                        fixed (byte* p = &diskBytes[dsecOff + di * 40])
                                                                        {
                                                                            onDiskSections[di] = Marshal.PtrToStructure<image_section_header>((IntPtr)p);
                                                                        }
                                                                    }
                                                                    onDiskNrofSections = diskNs;
                                                                    int lastRaw = onDiskSections[diskNs - 1].pointer_to_raw_data;
                                                                    int lastRs = onDiskSections[diskNs - 1].size_of_raw_data;
                                                                    if (lastRaw > 0 && lastRs > 0)
                                                                        onDiskTotalRawSize = lastRaw + lastRs;
                                                                    Console.WriteLine($"[INFO] On-disk section table loaded from {Path.GetFileName(imagePath)} ({diskNs} sections, raw size=0x{onDiskTotalRawSize:X})");
                                                                }
                                                            }
                                                            catch (Exception ex)
                                                            {
                                                                Console.WriteLine($"[WARNING] On-disk section parse failed: {ex.Message}");
                                                            }
                                                        }

                                                        // Prefer the on-disk section table for raw reconstruction.
                                                        // Themida/VMP scramble the in-memory raw offsets (anti-dump), which
                                                        // previously produced corrupt PEs (broken .rsrc -> SxS errors).
                                                        image_section_header[] rawSections = onDiskSections ?? sections;
                                                        int rawNrofSections = onDiskSections != null ? onDiskNrofSections : nrofsection;

                                                        // get total raw size (of all sections):
                                                        int totalrawsize = 0;
                                                        if (rawNrofSections > 0)
                                                        {
                                                            int rawsizeoflast = rawSections[rawNrofSections - 1].size_of_raw_data;
                                                            int rawaddressoflast = rawSections[rawNrofSections - 1].pointer_to_raw_data;
                                                            if (rawsizeoflast > 0 && rawaddressoflast > 0)
                                                                totalrawsize = rawsizeoflast + rawaddressoflast;
                                                            if (onDiskSections != null && onDiskTotalRawSize > 0)
                                                                totalrawsize = onDiskTotalRawSize;
                                                        }
                                                        string filename = "";

                                                        // calculate right size of image
                                                        int sizeofimage = BitConverter.ToInt32(PeHeader, e_lfanew + 0x050);

                                                        // CHANGE: Correctly initialize calculatedimagesize from PE Header's SizeOfHeaders field.
                                                        // Offset 60 from OptionalHeader start (24) = 84 (0x54)
                                                        int sizeOfHeaders = BitConverter.ToInt32(PeHeader, e_lfanew + 0x54);
                                                        int calculatedimagesize = sizeOfHeaders;

                                                        int rawsize, rawAddress, virtualsize, virtualAddress = 0;

                                                        for (int i = 0; i < nrofsection; i++)
                                                        {
                                                            virtualsize = sections[i].virtual_size;
                                                            virtualAddress = sections[i].virtual_address;

                                                            int toadd = virtualsize % sectionalignment;
                                                            if (toadd != 0) toadd = sectionalignment - toadd;

                                                            // Correctly calculate total size by finding the end of the last section

                                                            int sectionEnd = virtualAddress + virtualsize + toadd;
                                                            if (sectionEnd > calculatedimagesize)
                                                                calculatedimagesize = sectionEnd;
                                                        }

                                                        if (calculatedimagesize > sizeofimage) sizeofimage = calculatedimagesize;

                                                        try
                                                        {
                                                            byte[] crap = new byte[totalrawsize];
                                                        }
                                                        catch
                                                        {
                                                            totalrawsize = sizeofimage;
                                                        }

                                                        // --- RAWDUMP BLOCK ---
                                                        if (totalrawsize != 0)
                                                        {
                                                            try
                                                            {
byte[] rawdump = new byte[totalrawsize];
                                                                 // --- PROPER RAW DUMP RECONSTRUCTION ---
                                                                 // Copy headers first
                                                                 int headersSize = BitConverter.ToInt32(PeHeader, e_lfanew + 0x54);
                                                                 if (headersSize > PeHeader.Length) headersSize = PeHeader.Length;
                                                                 if (headersSize > rawdump.Length) headersSize = rawdump.Length;
                                                                 Array.Copy(PeHeader, rawdump, headersSize);

                                                                 // Fix the section table in the dump using the authoritative raw layout
                                                                 // (on-disk when available). This prevents corrupt .rsrc/.idata manifests.
                                                                 int rawSectionTableOff = PEOffset + 24 + sizeofoptionalheader;
                                                                 for (int s = 0; s < rawNrofSections && s < 96; s++)
                                                                 {
                                                                     int so = rawSectionTableOff + (0x28 * s);
                                                                     if (so + 40 > rawdump.Length) break;
                                                                     rawdump[so + 16] = (byte)rawSections[s].size_of_raw_data;
                                                                     rawdump[so + 17] = (byte)(rawSections[s].size_of_raw_data >> 8);
                                                                     rawdump[so + 18] = (byte)(rawSections[s].size_of_raw_data >> 16);
                                                                     rawdump[so + 19] = (byte)(rawSections[s].size_of_raw_data >> 24);
                                                                     rawdump[so + 20] = (byte)rawSections[s].pointer_to_raw_data;
                                                                     rawdump[so + 21] = (byte)(rawSections[s].pointer_to_raw_data >> 8);
                                                                     rawdump[so + 22] = (byte)(rawSections[s].pointer_to_raw_data >> 16);
                                                                     rawdump[so + 23] = (byte)(rawSections[s].pointer_to_raw_data >> 24);
                                                                 }

                                                                 // Copy each section from its VirtualAddress to its PointerToRawData
                                                                 for (int s = 0; s < rawNrofSections; s++)
                                                                 {
                                                                     int vAddress = rawSections[s].virtual_address;
                                                                     int rAddress = rawSections[s].pointer_to_raw_data;
                                                                     int rSize    = rawSections[s].size_of_raw_data;

                                                                     // Packers (e.g. VMP, Themida) zero SizeOfRawData in-memory while
                                                                     // keeping VirtualSize intact — fall back so .rsrc and other
                                                                     // sections are not silently skipped.
                                                                     if (rSize == 0 && rawSections[s].virtual_size > 0)
                                                                     {
                                                                         rSize = rawSections[s].virtual_size;
                                                                         Console.WriteLine($"[INFO] Section {s}: SizeOfRawData=0, using VirtualSize={rSize:X} instead");
                                                                     }

                                                                     if (rSize == 0 || rAddress == 0) continue;

                                                                     // Clamp so we never write past the rawdump buffer
                                                                     if ((long)rAddress + rSize > rawdump.Length)
                                                                         rSize = rawdump.Length - rAddress;
                                                                     if (rSize <= 0) continue;

                                                                     byte[] sectionData = new byte[rSize];
                                                                     ReadProcessMemoryW(hProcess, j + (ulong)k + (ulong)vAddress, sectionData, (UIntPtr)rSize, out BytesRead);

                                                                     try
                                                                     {
                                                                         Array.Copy(sectionData, 0, rawdump, rAddress, rSize);
                                                                     }
                                                                     catch { }
                                                                 }
                                                                isok = true;
                                                                
                                                                if (isok)
                                                                {
                                                                    dumpdir = ddirs.dumps;

                                                                    filename = dumpdir + "\\rawdump_" + (j + (ulong)k).ToString("X");
                                                                    if (File.Exists(filename))
                                                                        filename = dumpdir + "\\rawdump" + CurrentCount.ToString() + "_" + (j + (ulong)k).ToString("X");

                                                                    if (IsDll)
                                                                        filename += ".dll";
                                                                    else
                                                                        filename += ".exe";

                                                                    try
                                                                    {
                                                                        File.WriteAllBytes(filename, rawdump);
                                                                        sessionDumpedFiles.Add(filename);
                                                                        regionHadPe = true;
                                                                        Console.WriteLine($"[SUCCESS] Raw dumped: {Path.GetFileName(filename)}");

                                                                        // --- OVERLAY FIX ---
                                                                        // Windows only maps PE sections into virtual memory; any data
                                                                        // appended after the last section on disk (overlay / payload)
                                                                        // is never present in the process address space.
                                                                        // We must read it from the original on-disk file and re-append it.
                                                                        try
                                                                        {
                                                                            string exePath = GetProcessImagePath((int)processId);
                                                                            if (!string.IsNullOrEmpty(exePath) && File.Exists(exePath))
                                                                            {
                                                                                // Find where the last section ends on disk
                                                                                int overlayStart = 0;
                                                                                for (int s = 0; s < rawNrofSections; s++)
                                                                                {
                                                                                    int sectionEnd = rawSections[s].pointer_to_raw_data + rawSections[s].size_of_raw_data;
                                                                                    if (sectionEnd > overlayStart)
                                                                                        overlayStart = sectionEnd;
                                                                                }

                                                                                using FileStream onDisk = new(exePath, FileMode.Open, FileAccess.Read,
                                                                                                              FileShare.ReadWrite | FileShare.Delete);
                                                                                long onDiskSize = onDisk.Length;

                                                                                if (overlayStart > 0 && onDiskSize > overlayStart)
                                                                                {
                                                                                    byte[] overlay = new byte[onDiskSize - overlayStart];
                                                                                    onDisk.Seek(overlayStart, SeekOrigin.Begin);
                                                                                    onDisk.Read(overlay, 0, overlay.Length);

                                                                                    using FileStream rawOut = new(filename, FileMode.Append, FileAccess.Write);
                                                                                    rawOut.Write(overlay, 0, overlay.Length);
                                                                                    Console.WriteLine($"[INFO] Overlay: appended {overlay.Length} bytes from offset 0x{overlayStart:X} in {Path.GetFileName(exePath)}");
                                                                                }
                                                                                else
                                                                                {
                                                                                    Console.WriteLine($"[INFO] Overlay: no data past last section (disk size=0x{onDiskSize:X}, last section end=0x{overlayStart:X})");
                                                                                }
                                                                            }
                                                                            else
                                                                            {
                                                                                Console.WriteLine($"[WARNING] Overlay: could not resolve on-disk path for PID {processId} — overlay not appended");
                                                                            }
                                                                        }
                                                                        catch (Exception overlayEx)
                                                                        {
                                                                            Console.WriteLine($"[WARNING] Overlay append failed: {overlayEx.Message}");
                                                                        }
                                                                    }
                                                                    catch (Exception ex)
                                                                    {
                                                                        Console.WriteLine($"[ERROR] Raw dump write failed for {Path.GetFileName(filename)}: {ex.Message}");
                                                                    }
                                                                }
                                                            }
                                                            catch (Exception ex)
                                                            {
                                                                Console.WriteLine($"[ERROR] Raw dump failed at 0x{(j + (ulong)k):X16}: {ex.Message}");
                                                            }
                                                        }

                                                        // --- VMP ANTI-DUMP FIX: Calculate True SizeOfImage ---
                                                        // VMP spoofs SizeOfImage to be artificially small or huge in memory.
                                                        // We must find the highest section extent to allocate the correct buffer.
                                                        long trueSizeOfImage = sizeofimage;
                                                        for (int l = 0; l < nrofsection; l++)
                                                        {
                                                            long sectionExtent = (long)sections[l].virtual_address + sections[l].virtual_size;
                                                            if (sectionExtent > trueSizeOfImage)
                                                                trueSizeOfImage = sectionExtent;
                                                        }
                                                        
                                                        // Align to page size to be safe
                                                        trueSizeOfImage = (trueSizeOfImage + 0xFFF) & ~0xFFF;
                                                        
                                                        // Sane limit: Don't allocate more than 500MB for a single PE image
                                                        if (trueSizeOfImage > 500 * 1024 * 1024)
                                                            trueSizeOfImage = 500 * 1024 * 1024;
                                                        
                                                        if (trueSizeOfImage > sizeofimage)
                                                        {
                                                            Console.WriteLine($"[WARNING] Detected spoofed SizeOfImage! Fixing: {sizeofimage:X} -> {trueSizeOfImage:X}");
                                                            sizeofimage = (int)trueSizeOfImage;
                                                        }

                                                        // --- VDUMP BLOCK ---
                                                        byte[] virtualdump = null;
                                                        try 
                                                        {
                                                            virtualdump = new byte[sizeofimage];
                                                            Array.Copy(PeHeader, virtualdump, Math.Min(PeHeader.Length, sizeofimage));
                                                        }
                                                        catch (OutOfMemoryException)
                                                        {
                                                            Console.WriteLine($"[ERROR] OutOfMemoryException when trying to allocate {sizeofimage} bytes for Virtual Dump. Skipping.");
                                                            continue;
                                                        }

                                                        int rightrawsize = 0;
                                                        for (int l = 0; l < nrofsection; l++)
                                                        {
                                                            virtualsize = sections[l].virtual_size;
                                                            virtualAddress = sections[l].virtual_address;

                                                            // Memory dumper produces a fixed-layout image (raw offsets = RVAs).
                                                            // SizeOfRawData still has to satisfy PE FileAlignment even though the
                                                            // captured virtual bytes are only VirtualSize long; otherwise the loader
                                                            // can reject the dump or read the next section at the wrong boundary.
                                                            rawsize = virtualsize;
                                                            rawAddress = virtualAddress;
                                                            int alignedRawSize = virtualsize;
                                                            if (virtualsize > 0 && filealignment > 0)
                                                            {
                                                                long rounded = ((long)virtualsize + filealignment - 1) / filealignment * filealignment;
                                                                if (rounded <= int.MaxValue)
                                                                    alignedRawSize = (int)rounded;
                                                            }

                                                            using (BinaryWriter sectionWriter = new(new MemoryStream(virtualdump)))
                                                            {
                                                                // Fix section header in memory buffer
                                                                sectionWriter.BaseStream.Position = PEOffset + 24 + sizeofoptionalheader + (0x28 * l) + 16;
                                                                sectionWriter.Write(alignedRawSize); // SizeOfRawData
                                                                sectionWriter.BaseStream.Position = PEOffset + 24 + sizeofoptionalheader + (0x28 * l) + 20;
                                                                sectionWriter.Write(virtualAddress); // PointerToRawData
                                                            }

                                                            byte[] csection = new byte[0];
                                                            try
                                                            {
                                                                csection = new byte[rawsize];
                                                            }
                                                            catch
                                                            {
                                                                csection = new byte[virtualsize];
                                                            }
                                                            int rightsize = csection.Length;

                                                            // try reading whole section at once
                                                            isok = ReadProcessMemoryW(hProcess, j + (ulong)k + (ulong)virtualAddress, csection, (UIntPtr)rawsize, out BytesRead);
                                                            if (!isok || BytesRead != rawsize)
                                                            {
                                                                rightsize = 0;
                                                                byte[] currentpage = new byte[pagesizeInt];
                                                                for (int c = 0; c < rawsize; c += pagesizeInt)
                                                                {
                                                                    try
                                                                    {
                                                                        // read page-by-page
                                                                        isok = ReadProcessMemoryW(hProcess, j + (ulong)k + (ulong)virtualAddress + (ulong)c, currentpage, (UIntPtr)pagesizeInt, out BytesRead);
                                                                    }
                                                                    catch
                                                                    {
                                                                        break;
                                                                    }

                                                                    if (isok)
                                                                    {
                                                                        rightsize += (int)pagesizeInt;
                                                                        for (int i = 0; i < pagesizeInt; i++)
                                                                        {
                                                                            if ((c + i) < csection.Length)
                                                                                csection[c + i] = currentpage[i];
                                                                        }
                                                                    }
                                                                }
                                                            }

                                                            try
                                                            {
                                                                // Force copy to virtualAddress to avoid corrupting header
                                                                Array.Copy(csection, 0, virtualdump, virtualAddress, rightsize);
                                                            }
                                                            catch
                                                            {
                                                            }

                                                            rightrawsize = sizeofimage;
                                                        }

                                                        // VMP Fix: DO NOT attempt to 'fix' the entry point or imports here.
                                                        // Doing so breaks VMP's native initialization stubs.
                                                        // FixImportandEntryPoint((long)(j + (ulong)k), virtualdump);

                                                        dumpdir = ddirs.dumps;
                                                        filename = Path.Combine(dumpdir, "vdump_" + (j + (ulong)k).ToString("X") + (IsDll ? ".dll" : ".exe"));
                                                        
                                                        if (File.Exists(filename))
                                                            filename = Path.Combine(dumpdir, "vdump" + CurrentCount.ToString() + "_" + (j + (ulong)k).ToString("X") + (IsDll ? ".dll" : ".exe"));

                                                        try
                                                        {
                                                            using (FileStream fout = new FileStream(filename, FileMode.Create))
                                                            {
                                                                fout.Write(virtualdump, 0, Math.Min(rightrawsize, virtualdump.Length));
                                                            }
                                                            sessionDumpedFiles.Add(filename);
                                                            regionHadPe = true;
                                                            string netStatus = isNetAssembly ? "[.NET]" : "[Native]";
                                                            Console.WriteLine($"[SUCCESS] Virtual dumped {netStatus}: {Path.GetFileName(filename)}");
                                                        }
                                                        catch (Exception ex)
                                                        {
                                                            Console.WriteLine($"[ERROR] Virtual dump write failed for {Path.GetFileName(filename)}: {ex.Message}");
                                                        }
                                                        CurrentCount++;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Capture unbacked executable regions (MEM_PRIVATE + PAGE_EXECUTE*)
                        // that contained no PE/BSJB header so headerless shellcode / beacons
                        // are still extracted and scanned without dumping PAGE_READWRITE heaps.
                        const ulong MaxShellcodeRegionBytes = 4 * 1024 * 1024;
                        const ulong MaxShellcodeTotalBytes = 16 * 1024 * 1024;
                        const uint ExecProtectMask = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
                        bool isUnbackedExec = !regionHadPe &&
                                              (mbi.Type == MEM_PRIVATE) &&
                                              ((mbi.Protect & ExecProtectMask) != 0) &&
                                              regionSize >= 64 &&
                                              regionSize <= MaxShellcodeRegionBytes &&
                                              (totalShellcodeBytes + regionSize) <= MaxShellcodeTotalBytes;
                        if (isUnbackedExec)
                        {
                            byte[] scBuf = new byte[(int)regionSize];
                            uint scRead = 0;
                            if (ReadProcessMemoryW(hProcess, regionBase, scBuf, (UIntPtr)regionSize, out scRead) && scRead >= 64)
                            {
                                int nonPad = 0;
                                int sampleCap = Math.Min((int)scRead, 4096);
                                for (int s = 0; s < sampleCap; s++)
                                {
                                    byte b = scBuf[s];
                                    if (b != 0x00 && b != 0xCC)
                                    {
                                        nonPad++;
                                        if (nonPad >= 16)
                                            break;
                                    }
                                }
                                if (nonPad >= 16)
                                {
                                    string scPath = Path.Combine(ddirs.dumps, "shellcode_" + regionBase.ToString("X") + ".bin");
                                    if (!File.Exists(scPath))
                                    {
                                        try
                                        {
                                            using (var fs = new FileStream(scPath, FileMode.Create, FileAccess.Write, FileShare.None))
                                            {
                                                fs.Write(scBuf, 0, (int)scRead);
                                            }
                                            sessionDumpedFiles.Add(scPath);
                                            totalShellcodeBytes += scRead;
                                        }
                                        catch { }
                                    }
                                }
                            }
                        }
                    }

                    try
                    {
                        // CHANGE: Wrap the address calculation in an 'unchecked' block.
                        // This prevents an OverflowException when scanning at the top of the 64-bit address space,
                        // which is a necessary change for 64-bit compatibility.
                        unchecked
                        {
                            currentAddress = PtrToULong(mbi.BaseAddress) + PtrToULong(mbi.RegionSize);
                        }
                    }
                    catch (OverflowException)
                    {
                        // Reached the end of the 64-bit address space
                        // This catch is now less likely to be hit, but kept as a safeguard.
                        break;
                    }
                }

                Console.WriteLine("[INFO] Memory scan completed successfully.");

                // --- Renaming / Sorting Block ---
                if (restoreFilename)
                {
                    Action<string, string> renameFiles = (string sourceDir, string targetDir) => {
                        if (Directory.Exists(sourceDir))
                        {
                            DirectoryInfo di = new DirectoryInfo(sourceDir);
                            foreach (FileInfo fi in di.GetFiles())
                            {
                                try
                                {
                                    bool isDotNetFile = false;
                                    try
                                    {
                                        byte[] header = new byte[0x400];
                                        using (FileStream fs = new FileStream(fi.FullName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) 
                                        { 
                                            int read = fs.Read(header, 0, 0x400); 
                                            if (read < 0x40) throw new Exception("File too small");
                                        }

                                        int pe = BitConverter.ToInt32(header, 0x3C);
                                        if (pe > 0 && pe < 0x3C0)
                                        {
                                            int opt = pe + 4 + 20;
                                            bool is64 = BitConverter.ToUInt16(header, opt) == 0x20B;
                                            int dataDir = opt + (is64 ? 112 : 96);
                                            
                                            // Check 1: CLR Directory Index
                                            if (dataDir + (14 * 8) + 4 < 0x400)
                                            {
                                                if (BitConverter.ToUInt32(header, dataDir + (14 * 8)) > 0) isDotNetFile = true;
                                            }

                                            // Check 2: BSJB Heuristic scan
                                            if (!isDotNetFile)
                                            {
                                                for (int i = 0; i < 0x3FC; i++)
                                                {
                                                    if (header[i] == 0x42 && header[i+1] == 0x53 && header[i+2] == 0x4A && header[i+3] == 0x42)
                                                    {
                                                        isDotNetFile = true;
                                                        Console.WriteLine($"[DEBUG] Heuristic .NET detection: Found BSJB at 0x{i:X} in {fi.Name}");
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    catch (Exception ex) { Console.WriteLine($"[DEBUG] PE check failed for {fi.Name}: {ex.Message}"); }

                                    // DYNAMIC RUNTIME OVERRIDE
                                    if (isProcessDynamicallyManaged && !isDotNetFile) isDotNetFile = true;

                                    string finalDir = targetDir;
                                    bool isMicrosoft = false;
                                    try 
                                    {
                                        FileVersionInfo info = FileVersionInfo.GetVersionInfo(fi.FullName);
                                        
                                        // If Microsoft -> System Folder
                                        if (info.CompanyName?.IndexOf("microsoft corporation", StringComparison.OrdinalIgnoreCase) >= 0)
                                        {
                                            finalDir = ddirs.sysdirname;
                                            isMicrosoft = true;
                                        }
                                        // If Not .NET and Not System -> Native Folder
                                        else if (!isDotNetFile)
                                        {
                                            finalDir = ddirs.nativedirname;
                                        }

                                        if (!string.IsNullOrEmpty(info.OriginalFilename))
                                        {
                                            string safeName = string.Concat(info.OriginalFilename.Where(c => !Path.GetInvalidFileNameChars().Contains(c)));
                                            string newFilename = Path.Combine(finalDir, safeName);
                                            int count = 2;
                                            while (File.Exists(newFilename))
                                            {
                                                string extension = Path.GetExtension(newFilename) ?? ".dll";
                                                newFilename = Path.Combine(finalDir, $"{Path.GetFileNameWithoutExtension(safeName)}({count++}){extension}");
                                            }
                                            if (fi.FullName.ToLower() != newFilename.ToLower())
                                            {
                                                File.Move(fi.FullName, newFilename);
                                                Console.WriteLine($"[DEBUG] Moved to {Path.GetFileName(finalDir)}: {fi.Name} -> {Path.GetFileName(newFilename)}");
                                            }
                                            continue;
                                        }
                                        else if (!isMicrosoft)
                                        {
                                            // No original name and not Microsoft -> Move to Unknown
                                            finalDir = ddirs.unknowndirname;
                                        }
                                    }
                                    catch { }

                                    // Fallback move
                                    string fallbackPath = Path.Combine(finalDir, fi.Name);
                                    if (fi.FullName.ToLower() != fallbackPath.ToLower())
                                    {
                                        if (File.Exists(fallbackPath)) File.Delete(fallbackPath);
                                        File.Move(fi.FullName, fallbackPath);
                                        Console.WriteLine($"[DEBUG] Moved to {Path.GetFileName(finalDir)}: {fi.Name}");
                                    }
                                }
                                catch (Exception ex) 
                                { 
                                    Console.WriteLine($"[ERROR] Sorting failed for {fi.Name}: {ex.Message}"); 
                                }
                            }
                        }
                    };

                    renameFiles(ddirs.dumps, ddirs.dumps);
                }

                int dumpedFileCount = sessionDumpedFiles.Count;
                Console.WriteLine($"[INFO] Returning dump result for {ddirs.dumps}...");
                return dumpedFileCount + " files dumped in directory " + ddirs.dumps;
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }
    }
}
