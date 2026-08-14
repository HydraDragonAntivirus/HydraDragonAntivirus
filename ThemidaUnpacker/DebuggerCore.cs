using System.Runtime.InteropServices;

namespace ThemidaUnpacker;

public enum HWBPType
{
    Execute = 0,
    Write = 1,
    Reserved = 2,
    Access = 3,
}

public struct Breakpoint
{
    public ulong Address;
    public HWBPType BType;
    public bool Disabled;

    public void Change(ulong addr, HWBPType type)
    {
        Address = addr;
        BType = type;
    }

    public bool IsSet => !Disabled && Address > 0;
}

public enum SoftBPAction
{
    KeepContinue,
    ClearContinue,
    KeepContinueNoStep,
}

public abstract class DebuggerCore
{
    protected string FExecutable;
    protected string FParameters;
    protected uint FAttachPID;
    protected string FDLLExecutable;
    protected bool FIsDLL;

    protected PROCESS_INFORMATION FProcess;
    protected uint FCurrentThreadID;
    protected ulong FImageBase;
    protected List<MemoryRegion> FMemRegions = new();
    protected bool FHideThreadEnd;

    protected Breakpoint FHW1, FHW2, FHW3, FHW4;
    protected Dictionary<uint, IntPtr> FThreads = new();
    protected Dictionary<ulong, byte> FSoftBPs = new();
    protected ulong FSoftBPReenable;
    protected bool FBpHandled;
    protected ulong FStepOverAPI;

    public DebuggerCore(string executable, string parameters)
    {
        FExecutable = executable;
        FParameters = parameters;
    }

    public DebuggerCore(uint pid)
    {
        FAttachPID = pid;
    }

    protected abstract void OnDebugStart(ref IntPtr hPE, IntPtr hThread);
    protected virtual uint OnAccessViolation(IntPtr hThread, ref EXCEPTION_RECORD excRec)
    {
        Utils.Log(LogType.Info, $"AV at 0x{excRec.ExceptionAddress:X}, write={(ulong)excRec.ExceptionInformation0 != 0}, fault=0x{excRec.ExceptionInformation1:X}");
        return Native.DBG_EXCEPTION_NOT_HANDLED;
    }
    protected virtual void OnDLLLoad(string fileName, IntPtr baseAddress) { }
    protected abstract void OnHardwareBreakpoint(IntPtr hThread, ulong bpa, ref CONTEXT c);
    protected abstract SoftBPAction OnSoftwareBreakpoint(IntPtr hThread, ulong bpa);
    protected virtual void OnUnsolicitedSoftwareBreakpoint(IntPtr hThread, ulong bpa)
    {
        Utils.Log(LogType.Info, "Unsolicited int3");
    }
    protected virtual uint OnSinglestep(ulong bpa)
    {
        EnableBreakpoints();
        return Native.DBG_CONTINUE;
    }

    public IntPtr GetThread(uint threadId)
    {
        if (!FThreads.TryGetValue(threadId, out var handle))
            throw new Exception($"Thread {threadId} not found");
        return handle;
    }

    public void Run()
    {
        if (!PEExecute())
        {
            Utils.Log(LogType.Fatal, $"Creating the process failed (last error: {Marshal.GetLastWin32Error()})");
            return;
        }

        try
        {
            uint status = Native.DBG_CONTINUE;
            while (true)
            {
                if (!Native.WaitForDebugEvent(out DEBUG_EVENT ev, Native.INFINITE))
                {
                    Utils.Log(LogType.Fatal, $"OS Error in WaitForDebugEvent: {Marshal.GetLastWin32Error()}");
                    break;
                }

                FCurrentThreadID = ev.dwThreadId;

                switch (ev.dwDebugEventCode)
                {
                    case Native.EXCEPTION_DEBUG_EVENT:
                        status = Native.DBG_EXCEPTION_NOT_HANDLED;
                        switch (ev.U.Exception.ExceptionRecord.ExceptionCode)
                        {
                            case Native.EXCEPTION_ACCESS_VIOLATION:
                                status = OnAccessViolation(GetThread(ev.dwThreadId), ref ev.U.Exception.ExceptionRecord);
                                break;
                            case Native.EXCEPTION_BREAKPOINT:
                                if (FSoftBPs.ContainsKey((ulong)ev.U.Exception.ExceptionRecord.ExceptionAddress))
                                    status = OnSoftwareBreakpointEvent(ev);
                                else
                                    OnUnsolicitedSoftwareBreakpoint(GetThread(ev.dwThreadId), (ulong)ev.U.Exception.ExceptionRecord.ExceptionAddress);
                                break;
                            case Native.EXCEPTION_DATATYPE_MISALIGNMENT:
                                break;
                            case Native.EXCEPTION_SINGLE_STEP:
                                status = OnHardwareBreakpointEvent(ev);
                                break;
                            default:
                                if (ev.U.Exception.dwFirstChance == 0)
                                {
                                    Utils.Log(LogType.Fatal, "dwFirstChance = 0");
                                    status = Native.DBG_EXCEPTION_NOT_HANDLED;
                                }
                                else
                                {
                                    Utils.Log(LogType.Info, $"Code 0x{ev.U.Exception.ExceptionRecord.ExceptionCode:X8} at 0x{ev.U.Exception.ExceptionRecord.ExceptionAddress:X}");
                                    status = Native.DBG_EXCEPTION_NOT_HANDLED;
                                }
                                break;
                        }
                        break;

                    case Native.CREATE_THREAD_DEBUG_EVENT:
                        status = OnCreateThreadDebugEvent(ev);
                        break;

                    case Native.CREATE_PROCESS_DEBUG_EVENT:
                        status = OnCreateProcessDebugEvent(ev);
                        break;

                    case Native.EXIT_THREAD_DEBUG_EVENT:
                        status = OnExitThreadDebugEvent(ev);
                        break;

                    case Native.EXIT_PROCESS_DEBUG_EVENT:
                        status = OnExitProcessDebugEvent(ev);
                        Native.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status);
                        return;

                    case Native.LOAD_DLL_DEBUG_EVENT:
                        status = OnLoadDllDebugEvent(ev);
                        break;

                    case Native.UNLOAD_DLL_DEBUG_EVENT:
                        status = Native.DBG_CONTINUE;
                        break;

                    case Native.OUTPUT_DEBUG_STRING_EVENT:
                        status = OnOutputDebugStringEvent(ev);
                        break;

                    case Native.RIP_EVENT:
                        Utils.Log(LogType.Fatal, "SYSTEM ERROR");
                        status = Native.DBG_CONTINUE;
                        break;
                }

                Native.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status);
            }
        }
        catch (Exception ex)
        {
            Utils.Log(LogType.Fatal, $"Critical error in debug loop: {ex.Message}");
        }

        if (FIsDLL)
        {
            Thread.Sleep(1000);
            Native.DeleteFile(FDLLExecutable);
        }
    }

    private uint OnCreateThreadDebugEvent(DEBUG_EVENT ev)
    {
        Utils.Log(LogType.Info, $"[{ev.dwThreadId:D4}] Thread started ({ev.U.CreateThread.lpStartAddress:X}).");
        FThreads[ev.dwThreadId] = ev.U.CreateThread.hThread;
        UpdateDR(ev.U.CreateThread.hThread);
        return Native.DBG_CONTINUE;
    }

    private uint OnCreateProcessDebugEvent(DEBUG_EVENT ev)
    {
        Utils.Log(LogType.Info, $"Running on Windows build {Utils.GetWindowsBuildNumber()}");
        Utils.Log(LogType.Info, $"Debug session launched (PID: {ev.dwProcessId}, TID: {ev.dwThreadId})");

        FProcess.hProcess = ev.U.CreateProcessInfo.hProcess;
        FProcess.hThread = ev.U.CreateProcessInfo.hThread;
        FProcess.dwProcessId = ev.dwProcessId;
        FProcess.dwThreadId = ev.dwThreadId;

        Native.NtQueryInformationProcess(FProcess.hProcess, 0, out PROCESS_BASIC_INFORMATION pbi,
            Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _);
        Utils.Log(LogType.Info, $"PEB: {(ulong)pbi.PebBaseAddress:X}");

        // Patch PEB.BeingDebugged
        byte[] one = new byte[1];
        if (Native.ReadProcessMemory(FProcess.hProcess, pbi.PebBaseAddress + 2, one, 1, out _))
        {
            if (one[0] == 1)
            {
                Utils.Log(LogType.Good, "Patching PEB.BeingDebugged");
                one[0] = 0;
                Native.WriteProcessMemory(FProcess.hProcess, pbi.PebBaseAddress + 2, one, 1, out _);
            }
        }
        else
            Utils.Log(LogType.Fatal, "Reading PEB failed");

        // Read ImageBase from PEB (offset 16 on x64)
        byte[] baseBytes = new byte[8];
        if (Native.ReadProcessMemory(FProcess.hProcess, pbi.PebBaseAddress + 16, baseBytes, 8, out _))
        {
            FImageBase = BitConverter.ToUInt64(baseBytes, 0);
            Utils.Log(LogType.Info, $"Process Image Base: 0x{FImageBase:X}");
        }
        else
            throw new Exception("Reading process image base failed");

        // Clear PEB.pShimData (offset 0x2D8 on x64)
        byte[] shimBytes = new byte[8];
        if (Native.ReadProcessMemory(FProcess.hProcess, pbi.PebBaseAddress + 0x2D8, shimBytes, 8, out _) &&
            BitConverter.ToUInt64(shimBytes, 0) != 0)
        {
            shimBytes = new byte[8];
            if (Native.WriteProcessMemory(FProcess.hProcess, pbi.PebBaseAddress + 0x2D8, shimBytes, 8, out _))
                Utils.Log(LogType.Info, "Cleared PEB.pShimData to prevent apphelp hooks");
        }

        // Full anti-anti-debug: PEB heap flags + API HWBP hooks handled in the
        // debug loop (code bytes are never patched, so Themida's prologue CRC
        // checks pass). See Themida64.OnHardwareBreakpoint for the hook logic.
        try
        {
            AntiDebug.CleanPeb(FProcess.hProcess, (ulong)pbi.PebBaseAddress);
        }
        catch (Exception ex)
        {
            Utils.Log(LogType.Warning, $"Anti-debug PEB cleanup skipped: {ex.Message}");
        }

        FThreads[ev.dwThreadId] = ev.U.CreateProcessInfo.hThread;

        IntPtr hPE = ev.U.CreateProcessInfo.hFile;
        OnDebugStart(ref hPE, ev.U.CreateProcessInfo.hThread);

        return Native.DBG_CONTINUE;
    }

    private uint OnExitThreadDebugEvent(DEBUG_EVENT ev)
    {
        if (!FHideThreadEnd)
            Utils.Log(LogType.Info, $"[{ev.dwThreadId:D4}] Thread ended (code {ev.U.ExitThread.dwExitCode}).");
        FThreads.Remove(ev.dwThreadId);
        return Native.DBG_CONTINUE;
    }

    private uint OnHardwareBreakpointEvent(DEBUG_EVENT ev)
    {
        ulong eip = (ulong)ev.U.Exception.ExceptionRecord.ExceptionAddress;
        IntPtr hThread = GetThread(ev.dwThreadId);
        var c = new CONTEXT();
        c.ContextFlags = Native.CONTEXT_CONTROL | Native.CONTEXT_INTEGER | Native.CONTEXT_DEBUG_REGISTERS;
        if (!Native.GetThreadContext(hThread, ref c))
            Utils.Log(LogType.Fatal, "GetThreadContext failed");

        // Passthrough single-step: we just stepped over the first instruction of a
        // hooked API so its real code can run. Resume normally.
        if (FStepOverAPI != 0 && eip >= FStepOverAPI && eip <= FStepOverAPI + 16)
        {
            FStepOverAPI = 0;
            return Native.DBG_CONTINUE;
        }

        if (((c.Dr6 >> 14) & 1) == 0 && (FHW1.IsSet || FHW2.IsSet || FHW3.IsSet || FHW4.IsSet))
        {
            Breakpoint bp = default;
            switch (c.Dr6 & 0xF)
            {
                case 1: bp = FHW1; break;
                case 2: bp = FHW2; break;
                case 4: bp = FHW3; break;
                case 8: bp = FHW4; break;
                default:
                    Utils.Log(LogType.Fatal, $"Unknown hwbp at 0x{eip:X} (Dr6: {c.Dr6:X8})");
                    return Native.DBG_EXCEPTION_NOT_HANDLED;
            }

            FBpHandled = false;
            OnHardwareBreakpoint(hThread, bp.Address, ref c);

            // Disable and step over (unless the handler already redirected execution).
            if (bp.BType == HWBPType.Execute && !FBpHandled && DisableBreakpoint((ulong)eip))
            {
                UpdateDR(hThread);
                c.ContextFlags = Native.CONTEXT_CONTROL;
                c.EFlags |= 0x100;
                if (!Native.SetThreadContext(hThread, ref c))
                    Utils.Log(LogType.Fatal, "SetThreadContext failed");
            }
            else if (FBpHandled)
            {
                c.ContextFlags = Native.CONTEXT_CONTROL | Native.CONTEXT_INTEGER;
                if (!Native.SetThreadContext(hThread, ref c))
                    Utils.Log(LogType.Fatal, "SetThreadContext failed");
            }

            return Native.DBG_CONTINUE;
        }
        else if (FSoftBPReenable != 0)
        {
            // Re-enable soft bp after stepping over it.
            byte[] cc = new byte[] { 0xCC };
            Native.WriteProcessMemory(FProcess.hProcess, (IntPtr)FSoftBPReenable, cc, 1, out _);
            FSoftBPReenable = 0;
            return Native.DBG_CONTINUE;
        }
        else
            return OnSinglestep(eip);
    }

    private uint OnSoftwareBreakpointEvent(DEBUG_EVENT ev)
    {
        ulong eip = (ulong)ev.U.Exception.ExceptionRecord.ExceptionAddress;
        IntPtr hThread = GetThread(ev.dwThreadId);

        var c = new CONTEXT();
        c.ContextFlags = Native.CONTEXT_CONTROL;
        Native.GetThreadContext(hThread, ref c);
        c.Rip -= 1;
        Native.SetThreadContext(hThread, ref c);

        byte original = FSoftBPs[eip];
        if (!WriteByte((IntPtr)eip, original))
            Utils.Log(LogType.Fatal, "Restoring original byte failed");

        var action = OnSoftwareBreakpoint(hThread, eip);

        if (action == SoftBPAction.ClearContinue)
            FSoftBPs.Remove(eip);
        else if (action == SoftBPAction.KeepContinue)
        {
            FSoftBPReenable = c.Rip;
            c.EFlags |= 0x100;
            Native.SetThreadContext(hThread, ref c);
        }
        else if (action == SoftBPAction.KeepContinueNoStep)
        {
            if (!WriteByte((IntPtr)eip, 0xCC))
                Utils.Log(LogType.Fatal, "KeepContinueNoStep failed");
        }

        return Native.DBG_CONTINUE;
    }

    private uint OnLoadDllDebugEvent(DEBUG_EVENT ev)
    {
        string dll = "?";
        try
        {
            // lpImageName points to a pointer in the target that points to the name string.
            byte[] ptrBuf = new byte[8];
            if (Native.ReadProcessMemory(FProcess.hProcess, ev.U.LoadDll.lpImageName, ptrBuf, 8, out _))
            {
                IntPtr lpImageName = (IntPtr)BitConverter.ToInt64(ptrBuf, 0);
                byte[] nameBuf = new byte[520];
                if (Native.ReadProcessMemory(FProcess.hProcess, lpImageName, nameBuf, 520, out _))
                {
                    dll = ev.U.LoadDll.fUnicode != 0
                        ? System.Text.Encoding.Unicode.GetString(nameBuf).Split('\0')[0]
                        : System.Text.Encoding.ASCII.GetString(nameBuf).Split('\0')[0];
                }
            }
        }
        catch { }

        Utils.Log(LogType.Info, $"[{(ulong)ev.U.LoadDll.lpBaseOfDll:X8}] Loaded {dll}");
        OnDLLLoad(dll, ev.U.LoadDll.lpBaseOfDll);
        if (ev.U.LoadDll.hFile != IntPtr.Zero)
            Native.CloseHandle(ev.U.LoadDll.hFile);
        return Native.DBG_CONTINUE;
    }

    private uint OnExitProcessDebugEvent(DEBUG_EVENT ev)
    {
        Utils.Log(LogType.Info, $"Process ended (code {ev.U.ExitProcess.dwExitCode}).");
        return Native.DBG_CONTINUE;
    }

    private uint OnOutputDebugStringEvent(DEBUG_EVENT ev)
    {
        uint len = ev.U.DebugString.nDebugStringLength;
        if (len > 0 && len < 256)
        {
            byte[] buf = new byte[len];
            if (RPM((ulong)ev.U.DebugString.lpDebugStringData, buf, len))
            {
                string s = System.Text.Encoding.ASCII.GetString(buf);
                Utils.Log(LogType.Info, $"[Debug Str] {s}");
            }
        }
        return Native.DBG_CONTINUE;
    }

    private bool PEExecute()
    {
        if (FAttachPID != 0)
            return Native.DebugActiveProcess(FAttachPID);

        PEInspect();

        string currentDir = FExecutable;
        int idx = currentDir.LastIndexOf('\\');
        if (idx > 0) currentDir = currentDir.Substring(0, idx);

        var si = new STARTUPINFO();
        si.cb = (uint)Marshal.SizeOf<STARTUPINFO>();
        si.dwFlags = Native.STARTF_USESHOWWINDOW;
        si.wShowWindow = Native.SW_SHOW;

        string cmdLine = FIsDLL
            ? $"\"{FDLLExecutable}\""
            : $"\"{FExecutable}\" {FParameters}";

        uint flags = Native.CREATE_DEFAULT_ERROR_MODE | Native.CREATE_NEW_CONSOLE | Native.NORMAL_PRIORITY_CLASS |
                     Native.DEBUG_PROCESS | Native.DEBUG_ONLY_THIS_PROCESS;

        bool ok = Native.CreateProcess(null, cmdLine, IntPtr.Zero, IntPtr.Zero, false, flags,
            IntPtr.Zero, currentDir, ref si, out PROCESS_INFORMATION pi);
        FProcess = pi;
        return ok;
    }

    private void PEInspect()
    {
        var fs = new FileStream(FExecutable, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var header = new byte[0x1000];
        fs.Read(header, 0, header.Length);
        fs.Dispose();

        uint lfanew = BitConverter.ToUInt32(header, 0x3C);
        if (lfanew > 0xF00)
            throw new Exception("Selected file is not a PE or is malformed");

        uint sig = BitConverter.ToUInt32(header, (int)lfanew);
        if (sig != 0x4550)
            throw new Exception("PE file signature mismatch");

        ushort machine = BitConverter.ToUInt16(header, (int)lfanew + 4);
        if (machine != 0x8664)
            throw new Exception("File is for the wrong architecture, please use the 64-bit version of the unpacker.");

        ushort chars = BitConverter.ToUInt16(header, (int)lfanew + 22);
        FIsDLL = (chars & Native.IMAGE_FILE_DLL) != 0;
    }

    private void MakeDLLExecutable()
    {
        throw new NotImplementedException("DLL unpacking is not yet supported in this port.");
    }

    public void Detach()
    {
        foreach (var h in FThreads.Values)
            Native.SuspendThread(h);

        if (Native.DebugActiveProcessStop(FProcess.dwProcessId))
            Utils.Log(LogType.Info, "Detached.");
        else
            Utils.Log(LogType.Fatal, "Detaching failed.");
    }

    private void FetchMemoryRegions()
    {
        ulong address = 0;
        while (Native.VirtualQueryEx(FProcess.hProcess, (IntPtr)address, out MEMORY_BASIC_INFORMATION mbi, (nuint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()) != 0
               && address + mbi.RegionSize > address)
        {
            FMemRegions.Add(new MemoryRegion { Address = (ulong)mbi.BaseAddress, Size = (ulong)mbi.RegionSize });
            address += (ulong)mbi.RegionSize;
        }
    }

    public bool RPM(ulong address, byte[] buf, ulong size)
    {
        return Native.ReadProcessMemory(FProcess.hProcess, (IntPtr)address, buf, (nuint)size, out _);
    }

    public void SetBreakpoint(ulong address, HWBPType type = HWBPType.Execute)
    {
        if (FHW1.Address == 0) FHW1.Change(address, type);
        else if (FHW2.Address == 0) FHW2.Change(address, type);
        else if (FHW3.Address == 0) FHW3.Change(address, type);
        else if (FHW4.Address == 0) FHW4.Change(address, type);
        else throw new Exception("All breakpoints in use");

        foreach (var t in FThreads.Values)
            UpdateDR(t);
    }

    public bool DisableBreakpoint(ulong address)
    {
        if (FHW1.Address == address) { FHW1.Disabled = true; return true; }
        if (FHW2.Address == address) { FHW2.Disabled = true; return true; }
        if (FHW3.Address == address) { FHW3.Disabled = true; return true; }
        if (FHW4.Address == address) { FHW4.Disabled = true; return true; }
        return false;
    }

    public void EnableBreakpoints()
    {
        if (FHW1.Disabled || FHW2.Disabled || FHW3.Disabled || FHW4.Disabled)
        {
            FHW1.Disabled = false;
            FHW2.Disabled = false;
            FHW3.Disabled = false;
            FHW4.Disabled = false;
            foreach (var t in FThreads.Values)
                UpdateDR(t);
        }
    }

    public void ResetBreakpoint(ulong address)
    {
        if (FHW1.Address == address) FHW1.Address = 0;
        else if (FHW2.Address == address) FHW2.Address = 0;
        else if (FHW3.Address == address) FHW3.Address = 0;
        else if (FHW4.Address == address) FHW4.Address = 0;

        foreach (var t in FThreads.Values)
            UpdateDR(t);
    }

    public bool IsHWBreakpoint(ulong address)
    {
        return FHW1.Address == address || FHW2.Address == address ||
               FHW3.Address == address || FHW4.Address == address;
    }

    private void ApplyDebugRegisters(ref CONTEXT c)
    {
        uint mask = 0;

        c.Dr0 = FHW1.Address;
        if (FHW1.IsSet) mask = 1;

        c.Dr1 = FHW2.Address;
        if (FHW2.IsSet) mask |= (1u << 2);

        c.Dr2 = FHW3.Address;
        if (FHW3.IsSet) mask |= (1u << 4);

        c.Dr3 = FHW4.Address;
        if (FHW4.IsSet) mask |= (1u << 6);

        c.Dr6 = c.Dr6 & 0xFFFFBFFF;
        c.Dr7 = mask | ((uint)FHW1.BType << 16) | ((uint)FHW2.BType << 20) |
                ((uint)FHW3.BType << 24) | ((uint)FHW4.BType << 28);
    }

    private void UpdateDR(IntPtr hThread)
    {
        var c = new CONTEXT();
        c.ContextFlags = Native.CONTEXT_DEBUG_REGISTERS;
        if (Native.GetThreadContext(hThread, ref c))
        {
            ApplyDebugRegisters(ref c);
            Native.SetThreadContext(hThread, ref c);
        }
        else
            Utils.Log(LogType.Fatal, "GetThreadContext failed");
    }

    public bool WriteByte(IntPtr address, byte value)
    {
        byte[] buf = new byte[] { value };
        bool ok = Native.VirtualProtectEx(FProcess.hProcess, address, 1, Native.PAGE_EXECUTE_READWRITE, out uint oldProt) &&
                  Native.WriteProcessMemory(FProcess.hProcess, address, buf, 1, out _) &&
                  Native.VirtualProtectEx(FProcess.hProcess, address, 1, oldProt, out _);
        Native.FlushInstructionCache(FProcess.hProcess, address, 1);
        return ok;
    }

    public void SetSoftBP(IntPtr address)
    {
        byte[] b = new byte[1];
        if (!Native.ReadProcessMemory(FProcess.hProcess, address, b, 1, out _))
            throw new Exception($"Read for soft bp at 0x{(ulong)address:X} failed");

        ulong a = (ulong)address;
        if (FSoftBPs.ContainsKey(a))
        {
            if (b[0] != 0xCC)
                Utils.Log(LogType.Fatal, $"Soft bp inconsistency at 0x{a:X}!");
            return;
        }

        FSoftBPs[a] = b[0];

        if (!WriteByte(address, 0xCC))
            throw new Exception($"Write for soft bp at 0x{a:X} failed");

        Native.FlushInstructionCache(FProcess.hProcess, address, 1);
    }

    public void SoftBPClear()
    {
        foreach (var bp in FSoftBPs)
            WriteByte((IntPtr)bp.Key, bp.Value);
        FSoftBPs.Clear();
    }
}