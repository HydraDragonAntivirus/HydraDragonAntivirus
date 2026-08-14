using System.Runtime.InteropServices;

namespace ThemidaUnpacker;

public static class Native
{
    public const uint TH32CS_SNAPMODULE = 0x8;
    public const uint TH32CS_SNAPMODULE32 = 0x10;

    public const uint CONTEXT_AMD64 = 0x100000;
    public const uint CONTEXT_CONTROL = CONTEXT_AMD64 | 0x1;
    public const uint CONTEXT_INTEGER = CONTEXT_AMD64 | 0x2;
    public const uint CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10;

    public const uint DBG_CONTINUE = 0x00010002;
    public const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
    public const uint DBG_CONTROL_BREAK = 0x40010008;

    public const uint EXCEPTION_DEBUG_EVENT = 1;
    public const uint CREATE_THREAD_DEBUG_EVENT = 2;
    public const uint CREATE_PROCESS_DEBUG_EVENT = 3;
    public const uint EXIT_THREAD_DEBUG_EVENT = 4;
    public const uint EXIT_PROCESS_DEBUG_EVENT = 5;
    public const uint LOAD_DLL_DEBUG_EVENT = 6;
    public const uint UNLOAD_DLL_DEBUG_EVENT = 7;
    public const uint OUTPUT_DEBUG_STRING_EVENT = 8;
    public const uint RIP_EVENT = 9;

    public const uint EXCEPTION_ACCESS_VIOLATION = 0xC0000005;
    public const uint EXCEPTION_BREAKPOINT = 0x80000003;
    public const uint EXCEPTION_SINGLE_STEP = 0x80000004;
    public const uint EXCEPTION_DATATYPE_MISALIGNMENT = 0x80000002;

    public const uint PAGE_NOACCESS = 0x01;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;

    public const uint IMAGE_FILE_DLL = 0x2000;
    public const uint IMAGE_SCN_MEM_WRITE = 0x80000000;
    public const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    public const uint IMAGE_SCN_MEM_READ = 0x40000000;
    public const uint IMAGE_SCN_CNT_INITIALIZED_DATA = 0x40;
    public const ulong IMAGE_ORDINAL_FLAG64 = 0x8000000000000000;

    public const uint IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
    public const uint IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
    public const uint IMAGE_DIRECTORY_ENTRY_TLS = 9;
    public const uint IMAGE_DIRECTORY_ENTRY_IAT = 12;
    public const uint IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;

    public const uint STARTF_USESHOWWINDOW = 0x1;
    public const ushort SW_SHOW = 5;
    public const uint CREATE_DEFAULT_ERROR_MODE = 0x04000000;
    public const uint CREATE_NEW_CONSOLE = 0x00000010;
    public const uint NORMAL_PRIORITY_CLASS = 0x20;
    public const uint DEBUG_PROCESS = 0x1;
    public const uint DEBUG_ONLY_THIS_PROCESS = 0x2;
    public const uint INFINITE = 0xFFFFFFFF;

    public const uint GENERIC_READ = 0x80000000;
    public const uint FILE_SHARE_READ = 0x1;
    public const uint FILE_SHARE_WRITE = 0x2;
    public const uint FILE_SHARE_DELETE = 0x4;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    public const uint FILE_BEGIN = 0;
    public const uint FILE_CURRENT = 1;
    public const uint FILE_END = 2;

    public const uint THREAD_SUSPEND_RESUME = 0x2;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcess(
        string lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WaitForDebugEvent(out DEBUG_EVENT lpDebugEvent, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ContinueDebugEvent(uint dwProcessId, uint dwThreadId, uint dwContinueStatus);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DebugActiveProcess(uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DebugActiveProcessStop(uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, nuint nSize, out nuint lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, nuint nSize, out nuint lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, nuint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, nuint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern nuint VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, nuint dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandleEx(uint dwFlags, string lpModuleName, out IntPtr phModule);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32 lpme);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, nuint dwSize);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass,
        out PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out uint returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetFilePointerEx(IntPtr hFile, long liDistanceToMove, out long lpNewFilePointer, uint dwMoveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CopyFile(string lpExistingFileName, string lpNewFileName, bool bFailIfExists);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeleteFile(string lpFileName);
}

[StructLayout(LayoutKind.Sequential)]
public struct STARTUPINFO
{
    public uint cb;
    public string lpReserved;
    public string lpDesktop;
    public string lpTitle;
    public uint dwX;
    public uint dwY;
    public uint dwXSize;
    public uint dwYSize;
    public uint dwXCountChars;
    public uint dwYCountChars;
    public uint dwFillAttribute;
    public uint dwFlags;
    public ushort wShowWindow;
    public ushort cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
}

[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION
{
    public IntPtr hProcess;
    public IntPtr hThread;
    public uint dwProcessId;
    public uint dwThreadId;
}

[StructLayout(LayoutKind.Sequential)]
public struct EXCEPTION_RECORD
{
    public uint ExceptionCode;
    public uint ExceptionFlags;
    public IntPtr ExceptionRecord;
    public IntPtr ExceptionAddress;
    public uint NumberParameters;
    public IntPtr ExceptionInformation0;
    public IntPtr ExceptionInformation1;
    public IntPtr ExceptionInformation2;
    public IntPtr ExceptionInformation3;
    public IntPtr ExceptionInformation4;
    public IntPtr ExceptionInformation5;
    public IntPtr ExceptionInformation6;
    public IntPtr ExceptionInformation7;
    public IntPtr ExceptionInformation8;
    public IntPtr ExceptionInformation9;
    public IntPtr ExceptionInformation10;
    public IntPtr ExceptionInformation11;
    public IntPtr ExceptionInformation12;
    public IntPtr ExceptionInformation13;
    public IntPtr ExceptionInformation14;
}

[StructLayout(LayoutKind.Sequential)]
public struct EXCEPTION_DEBUG_INFO
{
    public EXCEPTION_RECORD ExceptionRecord;
    public uint dwFirstChance;
}

[StructLayout(LayoutKind.Sequential)]
public struct CREATE_THREAD_DEBUG_INFO
{
    public IntPtr hThread;
    public IntPtr lpThreadLocalBase;
    public IntPtr lpStartAddress;
}

[StructLayout(LayoutKind.Sequential)]
public struct CREATE_PROCESS_DEBUG_INFO
{
    public IntPtr hFile;
    public IntPtr hProcess;
    public IntPtr hThread;
    public IntPtr lpBaseOfImage;
    public uint dwDebugInfoFileOffset;
    public uint nDebugInfoSize;
    public IntPtr lpThreadLocalBase;
    public IntPtr lpStartAddress;
    public IntPtr lpImageName;
    public ushort fUnicode;
}

[StructLayout(LayoutKind.Sequential)]
public struct EXIT_THREAD_DEBUG_INFO
{
    public uint dwExitCode;
}

[StructLayout(LayoutKind.Sequential)]
public struct EXIT_PROCESS_DEBUG_INFO
{
    public uint dwExitCode;
}

[StructLayout(LayoutKind.Sequential)]
public struct LOAD_DLL_DEBUG_INFO
{
    public IntPtr hFile;
    public IntPtr lpBaseOfDll;
    public uint dwDebugInfoFileOffset;
    public uint nDebugInfoSize;
    public IntPtr lpImageName;
    public ushort fUnicode;
}

[StructLayout(LayoutKind.Sequential)]
public struct UNLOAD_DLL_DEBUG_INFO
{
    public IntPtr lpBaseOfDll;
}

[StructLayout(LayoutKind.Sequential)]
public struct OUTPUT_DEBUG_STRING_INFO
{
    public IntPtr lpDebugStringData;
    public ushort fUnicode;
    public ushort nDebugStringLength;
}

[StructLayout(LayoutKind.Sequential)]
public struct RIP_INFO
{
    public uint dwError;
    public uint dwType;
}

[StructLayout(LayoutKind.Explicit)]
public struct DEBUG_EVENT_UNION
{
    [FieldOffset(0)] public EXCEPTION_DEBUG_INFO Exception;
    [FieldOffset(0)] public CREATE_THREAD_DEBUG_INFO CreateThread;
    [FieldOffset(0)] public CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
    [FieldOffset(0)] public EXIT_THREAD_DEBUG_INFO ExitThread;
    [FieldOffset(0)] public EXIT_PROCESS_DEBUG_INFO ExitProcess;
    [FieldOffset(0)] public LOAD_DLL_DEBUG_INFO LoadDll;
    [FieldOffset(0)] public UNLOAD_DLL_DEBUG_INFO UnloadDll;
    [FieldOffset(0)] public OUTPUT_DEBUG_STRING_INFO DebugString;
    [FieldOffset(0)] public RIP_INFO RipInfo;
}

[StructLayout(LayoutKind.Sequential)]
public struct DEBUG_EVENT
{
    public uint dwDebugEventCode;
    public uint dwProcessId;
    public uint dwThreadId;
    public DEBUG_EVENT_UNION U;
}

[StructLayout(LayoutKind.Sequential)]
public struct CONTEXT
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
}

[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_BASIC_INFORMATION
{
    public IntPtr ExitStatus;
    public IntPtr PebBaseAddress;
    public IntPtr AffinityMask;
    public IntPtr BasePriority;
    public IntPtr UniqueProcessId;
    public IntPtr InheritedFromUniqueProcessId;
}

[StructLayout(LayoutKind.Sequential)]
public struct MEMORY_BASIC_INFORMATION
{
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint AllocationProtect;
    public nuint RegionSize;
    public uint State;
    public uint Protect;
    public uint Type;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct MODULEENTRY32
{
    public uint dwSize;
    public uint th32ModuleID;
    public uint th32ProcessID;
    public uint GlblcntUsage;
    public uint ProccntUsage;
    public IntPtr modBaseAddr;
    public uint modBaseSize;
    public IntPtr hModule;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string szModule;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string szExePath;
}

[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_DOS_HEADER
{
    public ushort e_magic;
    public ushort e_cblp;
    public ushort e_cp;
    public ushort e_crlc;
    public ushort e_cparhdr;
    public ushort e_minalloc;
    public ushort e_maxalloc;
    public ushort e_ss;
    public ushort e_sp;
    public ushort e_csum;
    public ushort e_ip;
    public ushort e_cs;
    public ushort e_lfarlc;
    public ushort e_ovno;
    public ushort e_res_0;
    public ushort e_res_1;
    public ushort e_res_2;
    public ushort e_res_3;
    public ushort e_oemid;
    public ushort e_oeminfo;
    public ushort e_res2_0;
    public ushort e_res2_1;
    public ushort e_res2_2;
    public ushort e_res2_3;
    public ushort e_res2_4;
    public ushort e_res2_5;
    public ushort e_res2_6;
    public ushort e_res2_7;
    public ushort e_res2_8;
    public ushort e_res2_9;
    public int e_lfanew;
}

[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_FILE_HEADER
{
    public ushort Machine;
    public ushort NumberOfSections;
    public uint TimeDateStamp;
    public uint PointerToSymbolTable;
    public uint NumberOfSymbols;
    public ushort SizeOfOptionalHeader;
    public ushort Characteristics;
}

[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_DATA_DIRECTORY
{
    public uint VirtualAddress;
    public uint Size;
}

[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_OPTIONAL_HEADER64
{
    public ushort Magic;
    public byte MajorLinkerVersion;
    public byte MinorLinkerVersion;
    public uint SizeOfCode;
    public uint SizeOfInitializedData;
    public uint SizeOfUninitializedData;
    public uint AddressOfEntryPoint;
    public uint BaseOfCode;
    public ulong ImageBase;
    public uint SectionAlignment;
    public uint FileAlignment;
    public ushort MajorOperatingSystemVersion;
    public ushort MinorOperatingSystemVersion;
    public ushort MajorImageVersion;
    public ushort MinorImageVersion;
    public ushort MajorSubsystemVersion;
    public ushort MinorSubsystemVersion;
    public uint Win32VersionValue;
    public uint SizeOfImage;
    public uint SizeOfHeaders;
    public uint CheckSum;
    public ushort Subsystem;
    public ushort DllCharacteristics;
    public ulong SizeOfStackReserve;
    public ulong SizeOfStackCommit;
    public ulong SizeOfHeapReserve;
    public ulong SizeOfHeapCommit;
    public uint LoaderFlags;
    public uint NumberOfRvaAndSizes;
    public IMAGE_DATA_DIRECTORY ExportTable;
    public IMAGE_DATA_DIRECTORY ImportTable;
    public IMAGE_DATA_DIRECTORY ResourceTable;
    public IMAGE_DATA_DIRECTORY ExceptionTable;
    public IMAGE_DATA_DIRECTORY CertificateTable;
    public IMAGE_DATA_DIRECTORY BaseRelocationTable;
    public IMAGE_DATA_DIRECTORY Debug;
    public IMAGE_DATA_DIRECTORY Architecture;
    public IMAGE_DATA_DIRECTORY GlobalPtr;
    public IMAGE_DATA_DIRECTORY TLSTable;
    public IMAGE_DATA_DIRECTORY LoadConfigTable;
    public IMAGE_DATA_DIRECTORY BoundImport;
    public IMAGE_DATA_DIRECTORY IAT;
    public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
    public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
    public IMAGE_DATA_DIRECTORY Reserved;
}

[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_NT_HEADERS64
{
    public uint Signature;
    public IMAGE_FILE_HEADER FileHeader;
    public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
}

[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_SECTION_HEADER
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public byte[] Name;
    public uint VirtualSize;
    public uint VirtualAddress;
    public uint SizeOfRawData;
    public uint PointerToRawData;
    public uint PointerToRelocations;
    public uint PointerToLinenumbers;
    public ushort NumberOfRelocations;
    public ushort NumberOfLinenumbers;
    public uint Characteristics;
}

[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_IMPORT_DESCRIPTOR
{
    public uint Characteristics;
    public uint TimeDateStamp;
    public uint ForwarderChain;
    public uint Name;
    public uint FirstThunk;
}

[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_EXPORT_DIRECTORY
{
    public uint Characteristics;
    public uint TimeDateStamp;
    public ushort MajorVersion;
    public ushort MinorVersion;
    public uint Name;
    public uint Base;
    public uint NumberOfFunctions;
    public uint NumberOfNames;
    public uint AddressOfFunctions;
    public uint AddressOfNames;
    public uint AddressOfNameOrdinals;
}

[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_TLS_DIRECTORY64
{
    public ulong StartAddressOfRawData;
    public ulong EndAddressOfRawData;
    public ulong AddressOfIndex;
    public ulong AddressOfCallBacks;
    public uint SizeOfZeroFill;
    public uint Characteristics;
}

[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_TLS_DIRECTORY32
{
    public uint StartAddressOfRawData;
    public uint EndAddressOfRawData;
    public uint AddressOfIndex;
    public uint AddressOfCallBacks;
    public uint SizeOfZeroFill;
    public uint Characteristics;
}