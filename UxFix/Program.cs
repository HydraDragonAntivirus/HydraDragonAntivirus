using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace UxFix
{
    internal static class Program
    {
        // ---- Win32 / NT APIs ----
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcessW(
            string lpApplicationName, string lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
            bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
            byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
            uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint CREATE_SUSPENDED = 0x4;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint INFINITE = 0xFFFFFFFF;

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        private static bool _verbose;

        private static void Log(string msg)
        {
            if (_verbose) Console.WriteLine(msg);
        }

        private static int Main(string[] args)
        {
            string exePath = Environment.GetEnvironmentVariable("APPDATA") + @"\.sonoyuncu\sonoyuncuclient.exe";
            bool wait = true;
            uint waitTimeout = INFINITE;
            bool patch = true;

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--no-wait": wait = false; break;
                    case "--no-patch": patch = false; break;
                    case "--verbose": _verbose = true; break;
                    case "--wait-timeout":
                        if (i + 1 < args.Length) uint.TryParse(args[++i], out waitTimeout);
                        break;
                    default:
                        exePath = args[i];
                        break;
                }
            }

            if (!File.Exists(exePath))
            {
                Console.WriteLine("UxFix: target not found: " + exePath);
                return 1;
            }

            string workDir = Path.GetDirectoryName(exePath);

            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf<STARTUPINFO>();
            PROCESS_INFORMATION pi;

            if (!CreateProcessW(exePath, null, IntPtr.Zero, IntPtr.Zero, false,
                CREATE_SUSPENDED, IntPtr.Zero, workDir, ref si, out pi))
            {
                Console.WriteLine("UxFix: CreateProcess failed, error=" + Marshal.GetLastWin32Error());
                return 1;
            }

            try
            {
                Console.WriteLine("UxFix: created PID " + pi.dwProcessId + " (suspended)");

                IntPtr ntdll = FindNtdllBase(pi.hProcess, pi.hThread);
                if (ntdll == IntPtr.Zero)
                {
                    Console.WriteLine("UxFix: could not locate ntdll in child");
                    ResumeThread(pi.hThread);
                    return 2;
                }
                Console.WriteLine("UxFix: child ntdll base = 0x" + ntdll.ToString("X"));

                if (patch)
                {
                    int patched = PatchMovaps(pi.hProcess, ntdll);
                    Console.WriteLine("UxFix: patched " + patched + " movaps->movups");
                }
                else
                {
                    Console.WriteLine("UxFix: --no-patch, skipping");
                }

                ResumeThread(pi.hThread);

                if (wait)
                {
                    uint r = WaitForSingleObject(pi.hProcess, waitTimeout);
                    if (r == 0)
                    {
                        uint code = 0;
                        GetExitCodeProcess(pi.hProcess, out code);
                        Console.WriteLine("UxFix: child exited with code 0x" + code.ToString("X") + " (" + code + ")");
                        return (int)code;
                    }
                    else
                    {
                        Console.WriteLine("UxFix: wait timed out (0x" + r.ToString("X") + "), child still running");
                    }
                }
                return 0;
            }
            finally
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, IntPtr dwLength);

        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_IMAGE = 0x1000000;

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public uint PartitionId;
            public long RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        private static IntPtr FindNtdllBase(IntPtr hProcess, IntPtr hThread)
        {
            // While suspended at creation, PEB.Ldr is not yet initialized and only the
            // exe image (0x140000000) plus ntdll are mapped. Enumerate MEM_IMAGE
            // regions and return the one that is a PE image other than the exe.
            long addr = 0;
            long exeBase = 0x140000000L;
            while (true)
            {
                MEMORY_BASIC_INFORMATION mbi;
                IntPtr res = VirtualQueryEx(hProcess, (IntPtr)addr, out mbi, (IntPtr)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());
                if (res == IntPtr.Zero) break;
                if (mbi.RegionSize <= 0) break;

                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE)
                {
                    long baseAddr = mbi.BaseAddress.ToInt64();
                    byte[] head = new byte[0x200];
                    IntPtr nread;
                    if (ReadProcessMemory(hProcess, mbi.BaseAddress, head, head.Length, out nread) &&
                        head[0] == 0x4D && head[1] == 0x5A)
                    {
                        int e_lfanew = BitConverter.ToInt32(head, 0x3C);
                        bool isPe = e_lfanew > 0 && e_lfanew < 0x200 &&
                                    head[e_lfanew] == 0x50 && head[e_lfanew + 1] == 0x45;
                        Log("UxFix: [vqe] image base=0x" + baseAddr.ToString("X") + " size=0x" +
                            mbi.RegionSize.ToString("X") + " PE=" + isPe);
                        if (isPe && baseAddr != exeBase)
                            return mbi.BaseAddress;
                    }
                    else
                    {
                        Log("UxFix: [vqe] image base=0x" + baseAddr.ToString("X") + " (no MZ read)");
                    }
                }

                long next = addr + (mbi.RegionSize > 0 ? mbi.RegionSize : 0x1000);
                if (next <= addr) break;
                addr = next;
                if (addr > 0x7FFFFFFFFFFFL) break;
            }
            Console.WriteLine("UxFix: could not locate ntdll base via region scan");
            return IntPtr.Zero;
        }

        private static int PatchMovaps(IntPtr hProcess, IntPtr ntdllBase)
        {
            // Read the child's ntdll PE headers to map the .text section.
            byte[] header = new byte[0x1000];
            IntPtr nread;
            if (!ReadProcessMemory(hProcess, ntdllBase, header, header.Length, out nread))
            {
                Console.WriteLine("UxFix: cannot read child ntdll headers");
                return 0;
            }

            int e_lfanew = BitConverter.ToInt32(header, 0x3C);
            int nsec = BitConverter.ToInt16(header, e_lfanew + 6);
            int sizeOpt = BitConverter.ToInt16(header, e_lfanew + 20);
            int sec = e_lfanew + 24 + sizeOpt;
            Log("UxFix: [pe] e_lfanew=0x" + e_lfanew.ToString("X") + " nsec=" + nsec + " sizeOpt=0x" + sizeOpt.ToString("X"));

            // Find .text VA/Raw within the first 0x1000 header buffer.
            int textVa = -1, textRaw = -1, textVSize = 0, textRawSize = 0;
            for (int i = 0; i < nsec; i++)
            {
                int s = sec + i * 40;
                byte[] nameBytes = new byte[8];
                Array.Copy(header, s, nameBytes, 0, Math.Min(8, header.Length - s));
                string name = Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');
                int vsize = BitConverter.ToInt32(header, s + 8);
                int va = BitConverter.ToInt32(header, s + 12);
                int rawSize = BitConverter.ToInt32(header, s + 16);
                int raw = BitConverter.ToInt32(header, s + 20);
                if (name == ".text")
                {
                    textVa = va; textRaw = raw; textVSize = vsize; textRawSize = rawSize;
                }
            }
            if (textVa < 0)
            {
                Console.WriteLine("UxFix: no .text section found in child ntdll");
                return 0;
            }
            Log("UxFix: [pe] .text VA=0x" + textVa.ToString("X") + " Raw=0x" + textRaw.ToString("X") +
                " VSize=0x" + textVSize.ToString("X") + " RawSize=0x" + textRawSize.ToString("X"));
            if (textVa != textRaw && textRaw != 0 && textVa != textRawSize)
            {
                Console.WriteLine("UxFix: unusual ntdll layout (.text VA=0x" + textVa.ToString("X") +
                                  " Raw=0x" + textRaw.ToString("X") + "), falling back to identity mapping");
            }

            // Read the .text section bytes from the child.
            int textLen = textVSize;
            byte[] text = new byte[textLen];
            IntPtr nread2;
            if (!ReadProcessMemory(hProcess, ntdllBase + textVa, text, textLen, out nread2))
            {
                Console.WriteLine("UxFix: cannot read child ntdll .text");
                return 0;
            }
            Log("UxFix: [pe] .text read bytes=" + nread2.ToInt64() +
                " probe@0x70F32=" + (textLen > 0x6FF34 ? text[0x6FF32].ToString("X2") + text[0x6FF33].ToString("X2") : "n/a"));

            var patches = new List<KeyValuePair<long, byte>>();
            int verified = 0;
            foreach (int fileOff in MovapsOffsets.MemoryOperand)
            {
                int rva = fileOff - textRaw + textVa;
                if (rva < 0 || rva > textLen) continue;
                int idx = rva - textVa; // text[] starts at VA=textVa
                if (idx < 0 || idx + 2 > textLen) continue;
                byte b0 = text[idx];
                byte b1 = text[idx + 1];
                if (b0 != 0x0F) continue;
                byte newOpcode;
                if (b1 == 0x28) newOpcode = 0x10;   // movaps load  -> movups load
                else if (b1 == 0x29) newOpcode = 0x11; // movaps store -> movups store
                else continue;
                verified++;
                patches.Add(new KeyValuePair<long, byte>(ntdllBase.ToInt64() + rva, newOpcode));
            }
            Log("UxFix: verified " + verified + "/" + MovapsOffsets.MemoryOperand.Length + " offsets as movaps");

            // Group by 4KB page, read-modify-write.
            var byPage = new Dictionary<long, Dictionary<int, byte>>();
            foreach (var kv in patches)
            {
                long page = kv.Key & ~0xFFFL;
                Dictionary<int, byte> changes;
                if (!byPage.TryGetValue(page, out changes))
                {
                    changes = new Dictionary<int, byte>();
                    byPage[page] = changes;
                }
                changes[(int)(kv.Key & 0xFFF)] = kv.Value;
            }

            int patched = 0;
            foreach (var pageKv in byPage)
            {
                long pageBase = pageKv.Key;
                byte[] page = new byte[0x1000];
                IntPtr pr;
                if (!ReadProcessMemory(hProcess, (IntPtr)pageBase, page, 0x1000, out pr))
                    continue;
                foreach (var change in pageKv.Value)
                    page[change.Key] = change.Value;

                uint oldProt;
                if (!VirtualProtectEx(hProcess, (IntPtr)pageBase, 0x1000, PAGE_EXECUTE_READWRITE, out oldProt))
                    continue;
                IntPtr written;
                bool ok = WriteProcessMemory(hProcess, (IntPtr)pageBase, page, 0x1000, out written);
                VirtualProtectEx(hProcess, (IntPtr)pageBase, 0x1000, oldProt, out uint tmp);
                if (ok)
                    patched += pageKv.Value.Count;
            }
            return patched;
        }
    }
}