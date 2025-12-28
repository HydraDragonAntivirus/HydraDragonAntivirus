/*
 * Created by SharpDevelop.
 * User: Bogdan
 * Date: 27.10.2010
 * Time: 18:14
 * * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using ProcessUtils;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Mega_Dumper
{
    /// <summary>
    /// Description of EmptyForm.
    /// </summary>
    public partial class EmptyForm : Form
    {
        public string ProcessName;
        public int procid;
        public int whattodo;

        public EmptyForm(string procname, int prid, int todo)
        {
            ProcessName = procname;
            procid = prid;
            whattodo = todo;
            //
            // The InitializeComponent() call is required for Windows Forms designer support.
            //
            InitializeComponent();

            //
            // TODO: Add constructor code after the InitializeComponent() call.
            //
        }

        private void Form3Load(object sender, EventArgs e)
        {
            textBox1.Text = "";
            if (whattodo == 1)
                Text = "Hook detection for " + ProcessName + " with PID=" + procid.ToString();
            else if (whattodo == 2)
                Text = "Environment Variables for " + ProcessName + " with PID=" + procid.ToString();
            else if (whattodo == 3)
                Text = "Files/directories from " + ProcessName + " with PID=" + procid.ToString();
            else if (whattodo == 4)
                Text = "Code section differences: process name " + ProcessName + "; PID=" + procid.ToString();
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            UIntPtr nSize,
            out UIntPtr lpNumberOfBytesRead
        );

        public static bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out uint lpNumberOfBytesRead
        )
        {
            bool ok = ReadProcessMemory(
                hProcess,
                lpBaseAddress,
                lpBuffer,
                (UIntPtr)nSize,
                out UIntPtr bytesRead
            );

            lpNumberOfBytesRead = (uint)bytesRead;
            return ok;
        }

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWow64Process([In] IntPtr processHandle, [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

        private static bool Is64BitProcess(IntPtr processHandle)
        {
            if (!Environment.Is64BitOperatingSystem)
                return false;

            if (!IsWow64Process(processHandle, out bool isWow64))
                return false; // Could not determine

            return !isWow64;
        }

        public enum ProcessAccess
        {
            Terminate = 0x1,
            CreateThread = 0x2,
            VMOperation = 0x8,
            VMRead = 0x10,
            VMWrite = 0x20,
            DuplicateHandle = 0x40,
            SetInformation = 0x200,
            QueryInformation = 0x400,
            Synchronize = 0x100000,
            AllAccess = CreateThread | DuplicateHandle | QueryInformation | SetInformation | Terminate | VMOperation | VMRead | VMWrite | Synchronize
        }

        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationProcess(IntPtr processHandle,
           int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, uint processInformationLength,
           out int returnLength);

        private string HoockDetect()
        {
            var sb = new StringBuilder();
            sb.AppendLine("Detecting hooks for process with the name " + ProcessName + " and PID=" + procid.ToString());

            IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (uint)procid);
            if (processHandle == IntPtr.Zero)
            {
                sb.AppendLine("Failed to open selected process!");
                return sb.ToString();
            }

            try
            {
                ProcModule.ModuleInfo targetmscorjit = null;
                ProcModule.ModuleInfo[] modules = ProcModule.GetModuleInfos(procid);

                if (modules?.Length > 0)
                {
                    foreach (var module in modules)
                    {
                        if (module.baseName.IndexOf("mscorjit", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            targetmscorjit = module;
                            break;
                        }
                    }
                }

                if (targetmscorjit == null)
                {
                    sb.AppendLine("Seems that the target process is not a .NET process!");
                }
                else
                {
                    int getJitrva = ExportTable.ProcGetExpAddress(processHandle, targetmscorjit.baseOfDll, "getJit");
                    byte[] Forread = new byte[0x500];
                    bool isok = ReadProcessMemory(processHandle,
                        new IntPtr(targetmscorjit.baseOfDll.ToInt64() + getJitrva), Forread, (uint)Forread.Length, out uint BytesRead);

                    if (isok)
                    {
                        int count = 0;
                        while (count < Forread.Length && Forread[count] != 0xC3) // RET instruction
                        {
                            count++;
                        }

                        if (count >= Forread.Length)
                        {
                            sb.AppendLine("Could not find end of getJit function stub.");
                            return sb.ToString();
                        }

                        long cmpointer = targetmscorjit.baseOfDll.ToInt64() + getJitrva + count + 1;
                        sb.AppendLine("Pointer to compile method: " + cmpointer.ToString("X"));

                        bool isTarget64Bit = Is64BitProcess(processHandle);
                        long CompileAddress;

                        if (isTarget64Bit)
                        {
                            CompileAddress = BitConverter.ToInt64(Forread, count + 1);
                        }
                        else
                        {
                            CompileAddress = BitConverter.ToInt32(Forread, count + 1);
                        }

                        sb.AppendLine("Address of compile method is: " + CompileAddress.ToString("X"));

                        long moduleStart = targetmscorjit.baseOfDll.ToInt64();
                        long moduleEnd = moduleStart + targetmscorjit.sizeOfImage;

                        if (CompileAddress < moduleStart || CompileAddress > moduleEnd)
                        {
                            sb.AppendLine("Address of compile method changed!!! Hook detected.");
                        }
                        else
                        {
                            sb.AppendLine("Address of compile method seems to be the original one!");
                        }
                    }
                    else
                    {
                        sb.AppendLine("Failed to read from selected process!");
                    }
                }
            }
            finally
            {
                CloseHandle(processHandle);
            }
            return sb.ToString();
        }

        private string EnumEnvironmentVars()
        {
            var sb = new StringBuilder();
            sb.AppendLine("Enumerating environment variables for " + ProcessName + " with PID=" + procid.ToString());

            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (uint)procid);
            if (hProcess == IntPtr.Zero)
            {
                sb.AppendLine("Failed to open selected process!");
                return sb.ToString();
            }

            try
            {
                PROCESS_BASIC_INFORMATION pbi = new();
                int result = NtQueryInformationProcess(hProcess, 0, ref pbi, (uint)Marshal.SizeOf(pbi), out _);

                if (result >= 0)
                {
                    bool isTarget64Bit = Is64BitProcess(hProcess);
                    int processParametersOffsetInPeb = isTarget64Bit ? 0x20 : 0x10;
                    int environmentOffsetInParams = isTarget64Bit ? 0x80 : 0x48;
                    int pointerSize = isTarget64Bit ? 8 : 4;

                    byte[] pebData = new byte[pointerSize];
                    if (ReadProcessMemory(hProcess, new IntPtr(pbi.PebBaseAddress.ToInt64() + processParametersOffsetInPeb), pebData, (uint)pointerSize, out _))
                    {
                        long processParametersPtr = (pointerSize == 8) ? BitConverter.ToInt64(pebData, 0) : BitConverter.ToUInt32(pebData, 0);

                        byte[] paramsData = new byte[pointerSize];
                        if (ReadProcessMemory(hProcess, new IntPtr(processParametersPtr + environmentOffsetInParams), paramsData, (uint)pointerSize, out _))
                        {
                            long environmentPtr = (pointerSize == 8) ? BitConverter.ToInt64(paramsData, 0) : BitConverter.ToUInt32(paramsData, 0);

                            StringBuilder envBlock = new StringBuilder();
                            byte[] buffer = new byte[1024];
                            long currentAddress = environmentPtr;

                            while (ReadProcessMemory(hProcess, new IntPtr(currentAddress), buffer, (uint)buffer.Length, out uint bytesRead) && bytesRead > 0)
                            {
                                string chunk = Encoding.Unicode.GetString(buffer, 0, (int)bytesRead);
                                int nullTerminator = chunk.IndexOf("\0\0");
                                if (nullTerminator != -1)
                                {
                                    envBlock.Append(chunk.Substring(0, nullTerminator));
                                    break;
                                }
                                envBlock.Append(chunk);
                                currentAddress += bytesRead;
                            }

                            string finalEnv = envBlock.ToString().Replace("\0", "\r\n");
                            return finalEnv;
                        }
                    }
                }
                return sb.ToString();
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }

        private string DirectoriesFilesList()
        {
            var sb = new StringBuilder();
            sb.AppendLine("Scanning for Directories/Files from " + ProcessName + " with PID=" + procid.ToString());

            string filelist = "";
            string directorylist = "";

            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (uint)procid);
            if (hProcess == IntPtr.Zero)
            {
                sb.AppendLine("Failed to open selected process!");
                return sb.ToString();
            }

            try
            {
                MainForm.SYSTEM_INFO pSI = new();
                MainForm.GetSystemInfo(ref pSI);

                ulong minaddress = (ulong)pSI.lpMinimumApplicationAddress.ToInt64();
                ulong maxaddress = (ulong)pSI.lpMaximumApplicationAddress.ToInt64();
                uint pagesize = pSI.dwPageSize > 0 ? pSI.dwPageSize : 4096;

                byte[] onepage = new byte[pagesize];

                for (ulong j = minaddress; j < maxaddress; j += pagesize)
                {
                    if (!ReadProcessMemory(hProcess, new IntPtr((long)j), onepage, pagesize, out _))
                    {
                        continue;
                    }

                    string pageAsString = Encoding.ASCII.GetString(onepage);
                    var matches = System.Text.RegularExpressions.Regex.Matches(pageAsString, @"[a-zA-Z]:\\[^:\*?""<>|\0]+");
                    foreach (System.Text.RegularExpressions.Match match in matches)
                    {
                        string thepath = match.Value.Trim();
                        try
                        {
                            if (File.Exists(thepath) && !filelist.Contains(thepath))
                            {
                                filelist += thepath + "\r\n";
                            }
                            else if (Directory.Exists(thepath) && !directorylist.Contains(thepath))
                            {
                                directorylist += thepath + "\r\n";
                            }
                        }
                        catch { }
                    }
                }
                sb.AppendLine("Directories:\r\n" + directorylist);
                sb.AppendLine("Files:\r\n" + filelist);
                return sb.ToString();
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }


        public string modulename = "";
        public IntPtr baseaddress = IntPtr.Zero;

        public int RVA2Section(MainForm.image_section_header[] sections, int rva)
        {
            for (int i = 0; i < sections.Length; i++)
            {
                if ((sections[i].virtual_address <= rva) && (sections[i].virtual_address + sections[i].virtual_size >= rva))
                    return i;
            }
            return -1;
        }

        private unsafe string CodeSectionDifferences()
        {
            var sb = new StringBuilder();
            sb.AppendLine("Code section differences in module " + modulename + " base address:" + baseaddress.ToString("X"));

            if (!File.Exists(modulename))
            {
                sb.AppendLine("The file: " + modulename + " does not exist!");
                sb.AppendLine("Finding differences aborted!");
            }
            else
            {
                byte[] filebytes = File.ReadAllBytes(modulename);
                if (filebytes.Length < 0x200 || filebytes[0] != 0x4D || filebytes[1] != 0x5A)
                {
                    sb.AppendLine("Invalid PE file: " + modulename);
                }
                else
                {
                    int PEOffset = BitConverter.ToInt32(filebytes, 0x03C);
                    if (PEOffset <= 0 || PEOffset >= filebytes.Length ||
                        filebytes[PEOffset] != 0x50 || filebytes[PEOffset + 1] != 0x45)
                    {
                        sb.AppendLine("Invalid PE file: " + modulename);
                    }
                    else
                    {
                        short nrofsection = BitConverter.ToInt16(filebytes, PEOffset + 0x6);
                        short sizeofoptionalheader = BitConverter.ToInt16(filebytes, PEOffset + 0x14);
                        int BaseOfCode = BitConverter.ToInt32(filebytes, PEOffset + 0x1C);

                        MainForm.image_section_header[] sections = new MainForm.image_section_header[nrofsection];

                        long ptr = PEOffset + sizeofoptionalheader + 4 +
                            Marshal.SizeOf(typeof(MainForm.IMAGE_FILE_HEADER));

                        byte[] datakeeper = new byte[Marshal.SizeOf(typeof(MainForm.image_section_header))];

                        for (int i = 0; i < nrofsection; i++)
                        {
                            Array.Copy(filebytes, ptr, datakeeper, 0, datakeeper.Length);
                            fixed (byte* p = datakeeper)
                            {
                                sections[i] = (MainForm.image_section_header)Marshal.PtrToStructure((IntPtr)p, typeof(MainForm.image_section_header));
                            }
                            ptr += datakeeper.Length;
                        }

                        int codesectionindex = RVA2Section(sections, BaseOfCode);
                        if (codesectionindex == -1)
                        {
                            sb.AppendLine("Failed to get code section for the file: " + modulename);
                        }
                        else
                        {
                            // TODO: Implement comparison logic here
                            sb.AppendLine("Comparison logic not yet implemented.");
                        }
                    }
                }
            }
            return sb.ToString();
        }

        private async void EmptyFormShown(object sender, EventArgs e)
        {
            // İşlemi arka plana alarak UI'nin donmasını engelle
            this.SuspendLayout();
            textBox1.Text = "İşlem yapılıyor, lütfen bekleyin...";

            string result = await Task.Run(() => {
                if (whattodo == 1)
                    return HoockDetect();
                else if (whattodo == 2)
                    return EnumEnvironmentVars();
                else if (whattodo == 3)
                    return DirectoriesFilesList();
                else if (whattodo == 4)
                    return CodeSectionDifferences();
                return "Bilinmeyen işlem.";
            });

            textBox1.Text = result;
            this.ResumeLayout();
        }
    }
}
