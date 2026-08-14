using System.Runtime.InteropServices;

namespace ThemidaUnpacker;

/// <summary>
/// Port of Magicmida's TTMDebugger64: Themida/WinLicense x64 unpacker driven by the
/// debug loop in DebuggerCore. ScyllaHide/InjectorCLIx64 is replaced by the in-process
/// PEB patches already performed by DebuggerCore.
/// </summary>
public class Themida64 : ThemidaCommon
{
    private ulong CloseHandleAPI, VirtualAllocAPI, FCorExeMain;

    private ulong FGuardStart, FGuardEnd;
    private bool FGuardStepping, FTMGuard, FTraceMSVCOEP;

    private ulong FMSVCInitCookie, FMSVCOEP;

    private int FTLSCounter, FTLSTotal;

    private ulong FNtQueryInformationProcess, FNtSetInformationThread, FNtGetContextThread;
    private bool FAntiDebugArmed;

    public Themida64(string executable, string parameters)
        : base(executable, parameters)
    {
        FThemidaV3 = true;
        FGuardAddrs = new List<ulong>();
    }

    public Themida64(uint pid)
        : base(pid)
    {
        FThemidaV3 = true;
        FGuardAddrs = new List<ulong>();
    }

    private bool InImageBounds(ulong address)
    {
        return address >= FImageBase && address < FImageBoundary;
    }

    private void SelectThemidaSection(ulong address)
    {
        for (int i = 0; i < FPESections.Count; i++)
        {
            var s = FPESections[i];
            if (address >= s.VirtualAddress + FImageBase &&
                address < s.VirtualAddress + s.VirtualSize + FImageBase)
            {
                TMSectR.Address = s.VirtualAddress + FImageBase;
                TMSectR.Size = s.VirtualSize;
                TMSect = new byte[TMSectR.Size];
                if (!RPM(TMSectR.Address, TMSect, TMSectR.Size))
                {
                    TMSect = null;
                }
                Utils.Log(LogType.Info, $"TMSect: 0x{TMSectR.Address:X} ({TMSectR.Size} bytes)");
                break;
            }
        }

        if (TMSect == null)
            throw new Exception($"Unable to find section for 0x{address:X}");
    }

    protected override void OnDebugStart(ref IntPtr hPE, IntPtr hThread)
    {
        VirtualAllocAPI = (ulong)Native.GetProcAddress(Native.GetModuleHandle("kernel32.dll"), "VirtualAlloc");
        FSleepAPI = (ulong)Native.GetProcAddress(Native.GetModuleHandle("kernel32.dll"), "Sleep");
        FlstrlenAPI = (ulong)Native.GetProcAddress(Native.GetModuleHandle("kernel32.dll"), "lstrlen");

        // API hooks via hardware breakpoints (no code bytes modified, so Themida's
        // ntdll prologue CRC/anti-tamper checks pass). These occupy HW1-HW3 and
        // stay armed for the whole session; the CloseHandle/guard flow uses HW4.
        IntPtr ntdll = Native.GetModuleHandle("ntdll.dll");
        if (ntdll != IntPtr.Zero)
        {
            FNtQueryInformationProcess = (ulong)Native.GetProcAddress(ntdll, "NtQueryInformationProcess");
            FNtSetInformationThread = (ulong)Native.GetProcAddress(ntdll, "NtSetInformationThread");
            FNtGetContextThread = (ulong)Native.GetProcAddress(ntdll, "NtGetContextThread");
            if (Environment.GetEnvironmentVariable("TU_QIP") != "0" && FNtQueryInformationProcess != 0)
                SetBreakpoint(FNtQueryInformationProcess, HWBPType.Execute);
            if (Environment.GetEnvironmentVariable("TU_SIT") != "0" && FNtSetInformationThread != 0)
                SetBreakpoint(FNtSetInformationThread, HWBPType.Execute);
            if (Environment.GetEnvironmentVariable("TU_GCT") != "0" && FNtGetContextThread != 0)
                SetBreakpoint(FNtGetContextThread, HWBPType.Execute);
            FAntiDebugArmed = true;
        }

        TMInit();
    }

    protected override uint OnAccessViolation(IntPtr hThread, ref EXCEPTION_RECORD excRec)
    {
        if (IsGuardedAddress((ulong)excRec.ExceptionInformation1))
            return ProcessGuardedAccess(hThread, ref excRec);
        return base.OnAccessViolation(hThread, ref excRec);
    }

    protected override void OnDLLLoad(string fileName, IntPtr baseAddress)
    {
        if (fileName.IndexOf("mscoree.dll", StringComparison.OrdinalIgnoreCase) >= 0)
        {
            Utils.Log(LogType.Info, "This might be a .NET program - setting _CorExeMain BP");
            IntPtr hCorEE = Native.GetModuleHandle("mscoree.dll");
            if (hCorEE == baseAddress)
            {
                FCorExeMain = (ulong)Native.GetProcAddress(hCorEE, "_CorExeMain");
                SetSoftBP((IntPtr)FCorExeMain);
            }
            else
                Utils.Log(LogType.Fatal, "DLL was loaded at different base than in target!");
        }

        base.OnDLLLoad(fileName, baseAddress);
    }

    protected override void OnHardwareBreakpoint(IntPtr hThread, ulong bpa, ref CONTEXT c)
    {
        ulong eip = c.Rip;

        if (FAntiDebugArmed && eip == FNtQueryInformationProcess)
        {
            FHandleNtQueryInformationProcess(hThread, ref c);
            return;
        }
        if (FAntiDebugArmed && eip == FNtSetInformationThread)
        {
            FHandleNtSetInformationThread(hThread, ref c);
            return;
        }
        if (FAntiDebugArmed && eip == FNtGetContextThread)
        {
            FHandleNtGetContextThread(hThread, ref c);
            return;
        }

        if (eip == CloseHandleAPI)
        {
            byte[] buf = new byte[8];
            if (RPM(c.Rsp, buf, 8))
            {
                ulong retAddr = BitConverter.ToUInt64(buf, 0);
                Utils.Log(LogType.Info, $"CloseHandle called from 0x{retAddr:X}");

                if (InImageBounds(retAddr))
                {
                    ResetBreakpoint(CloseHandleAPI);
                    SetBreakpoint(FImageBase + 0x1000, HWBPType.Write);
                }
            }
        }
        else if (eip == VirtualAllocAPI)
        {
            byte[] buf = new byte[8];
            ulong retAddr = 0;
            if (RPM(c.Rsp, buf, 8))
                retAddr = BitConverter.ToUInt64(buf, 0);
            Utils.Log(LogType.Info, $"AllocMem called from 0x{retAddr:X}");

            if (InImageBounds(retAddr))
            {
                ResetBreakpoint(VirtualAllocAPI);
                InstallCodeSectionGuard();
            }
        }
        else if (bpa == FImageBase + 0x1000)
        {
            Utils.Log(LogType.Good, $"Wrote to .text base from 0x{eip:X}");

            if (TMSectR.Address == 0)
                SelectThemidaSection(eip);

            ResetBreakpoint(FImageBase + 0x1000);
            SetBreakpoint(VirtualAllocAPI, HWBPType.Execute);
        }
        else
            Utils.Log(LogType.Info, $"Accessed 0x{bpa:X} from 0x{eip:X}");
    }

    /// <summary>Fakes NtQueryInformationProcess results for hidden classes
    /// (0x07 DebugPort, 0x1E DebugObjectHandle, 0x1F ProcessDebugFlags) by
    /// skipping the real call and returning STATUS_SUCCESS with a zeroed buffer.</summary>
    private void FHandleNtQueryInformationProcess(IntPtr hThread, ref CONTEXT c)
    {
        uint cls = (uint)(c.Rdx & 0xFFFFFFFF);
        ulong buffer = c.R8;
        ulong length = c.R9;

        if (cls is 0x07 or 0x1E or 0x1F)
        {
            Utils.Log(LogType.Good, $"NtQueryInformationProcess(class 0x{cls:X2}) hidden");
            byte[] zero = new byte[Math.Min(length, 64)];
            if (buffer != 0 && zero.Length > 0)
                Native.WriteProcessMemory(FProcess.hProcess, (IntPtr)buffer, zero, (nuint)zero.Length, out _);

            // Write ReturnLength (5th arg at [rsp+0x28]).
            byte[] rlBuf = new byte[8];
            if (RPM(c.Rsp + 0x28, rlBuf, 8))
            {
                ulong retLenPtr = BitConverter.ToUInt64(rlBuf, 0);
                if (retLenPtr != 0)
                {
                    byte[] lenBytes = BitConverter.GetBytes((ulong)length);
                    Native.WriteProcessMemory(FProcess.hProcess, (IntPtr)retLenPtr, lenBytes, 8, out _);
                }
            }

            // Simulate a real return: pop return address, set eax = STATUS_SUCCESS.
            byte[] retBuf = new byte[8];
            ulong retAddr = 0;
            if (RPM(c.Rsp, retBuf, 8))
                retAddr = BitConverter.ToUInt64(retBuf, 0);
            c.Rax = 0;
            c.Rip = retAddr;
            c.Rsp += 8;
            FBpHandled = true;
        }
        else
        {
            // Let other classes run the real API: keep the HWBP armed and just
            // single-step over the first instruction, so the real API code runs.
            FStepOverAPI = FNtQueryInformationProcess;
            c.EFlags |= 0x100;
            FBpHandled = true;
        }
    }

    /// <summary>Fakes NtGetContextThread: returns the caller's real register
    /// context but with all debug registers (Dr0-Dr3, Dr6, Dr7) zeroed, so
    /// Themida can't detect our hardware breakpoints.</summary>
    private void FHandleNtGetContextThread(IntPtr hThread, ref CONTEXT c)
    {
        ulong pContext = c.Rdx; // PCONTEXT output buffer

        Utils.Log(LogType.Good, "NtGetContextThread hidden (DR registers cleared)");

        // Build a context from the real thread state, then zero the DR fields.
        var real = new CONTEXT();
        real.ContextFlags = Native.CONTEXT_CONTROL | Native.CONTEXT_INTEGER | Native.CONTEXT_DEBUG_REGISTERS;
        if (Native.GetThreadContext(hThread, ref real))
        {
            real.Dr0 = 0;
            real.Dr1 = 0;
            real.Dr2 = 0;
            real.Dr3 = 0;
            real.Dr6 = 0;
            real.Dr7 = 0;

            byte[] buf = new byte[Marshal.SizeOf<CONTEXT>()];
            IntPtr ptr = Marshal.AllocHGlobal(buf.Length);
            try
            {
                Marshal.StructureToPtr(real, ptr, false);
                Marshal.Copy(ptr, buf, 0, buf.Length);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }

            if (pContext != 0)
                Native.WriteProcessMemory(FProcess.hProcess, (IntPtr)pContext, buf, (nuint)buf.Length, out _);
        }

        byte[] retBuf = new byte[8];
        ulong retAddr = 0;
        if (RPM(c.Rsp, retBuf, 8))
            retAddr = BitConverter.ToUInt64(retBuf, 0);
        c.Rax = 0;
        c.Rip = retAddr;
        c.Rsp += 8;
        FBpHandled = true;
    }

    /// <summary>Fakes NtSetInformationThread ThreadHideFromDebugger (class 0x11).</summary>
    private void FHandleNtSetInformationThread(IntPtr hThread, ref CONTEXT c)
    {
        uint cls = (uint)(c.Rdx & 0xFFFFFFFF);

        if (cls == 0x11)
        {
            Utils.Log(LogType.Good, "NtSetInformationThread(class 0x11) hidden");
            byte[] retBuf = new byte[8];
            ulong retAddr = 0;
            if (RPM(c.Rsp, retBuf, 8))
                retAddr = BitConverter.ToUInt64(retBuf, 0);
            c.Rax = 0;
            c.Rip = retAddr;
            c.Rsp += 8;
            FBpHandled = true;
        }
        else
        {
            // Let other classes run the real API.
            FStepOverAPI = FNtSetInformationThread;
            c.EFlags |= 0x100;
            FBpHandled = true;
        }
    }

    protected override uint OnSinglestep(ulong bpa)
    {
        if (FGuardStepping)
        {
            if (!Native.VirtualProtectEx(FProcess.hProcess, (IntPtr)FGuardStart,
                (nuint)(FGuardEnd - FGuardStart), Native.PAGE_NOACCESS, out _))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            FGuardStepping = false;
            return Native.DBG_CONTINUE;
        }

        return base.OnSinglestep(bpa);
    }

    protected override SoftBPAction OnSoftwareBreakpoint(IntPtr hThread, ulong bpa)
    {
        throw new Exception($"Unexpected SoftBP at 0x{bpa:X}");
    }

    /// <summary>Reads on-disk PE headers, fixes PE-header anti-dump, installs the code guard.</summary>
    private void TMInit()
    {
        var header = new byte[0x1000];
        using (var fs = new FileStream(FExecutable, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            fs.Read(header, 0, header.Length);
        }

        InitPEDetails(header);

        uint lfanew = BitConverter.ToUInt32(header, 0x3C);
        var ntHdr = PEHeader.MarshalBytesToStruct<IMAGE_NT_HEADERS64>(header);
        int secOff = (int)lfanew + 24 + ntHdr.FileHeader.SizeOfOptionalHeader;
        var sect0 = FPESections[0];

        // Delphi: FBaseOfData := Sect[0].VirtualAddress + NT.OptionalHeader.SizeOfCode;
        FBaseOfData = sect0.VirtualAddress + ntHdr.OptionalHeader.SizeOfCode;

        // PE Header Antidump: if section[2] name starts with 'i' in-memory, fix it to 'p'.
        if (FPESections.Count > 2)
        {
            byte[] nameBuf = new byte[1];
            ulong nameAddr = FImageBase + (ulong)secOff + (ulong)(2 * 40);
            if (RPM(nameAddr, nameBuf, 1) && nameBuf[0] == (byte)'i')
            {
                Native.VirtualProtectEx(FProcess.hProcess, (IntPtr)nameAddr, 1, Native.PAGE_READWRITE, out _);
                byte[] p = new byte[] { (byte)'p' };
                if (!Native.WriteProcessMemory(FProcess.hProcess, (IntPtr)nameAddr, p, 1, out _))
                    throw new Exception($"Fixing PE header antidump failed! Code: {Marshal.GetLastWin32Error()}");
            }
        }

        if (FPESections.Count > 0 && Utils.AnsiString(sect0.Name) == ".text")
        {
            // Code not encrypted/compressed
            Utils.Log(LogType.Good, "Text section not encrypted/compressed, installing page guard");
            InstallCodeSectionGuard();
        }
        else
        {
            CloseHandleAPI = (ulong)Native.GetProcAddress(Native.GetModuleHandle("kernel32.dll"), "CloseHandle");
            SetBreakpoint(CloseHandleAPI, HWBPType.Execute);
        }

        // TLS callbacks: assume MSVC layout where callbacks sit right before the TLS directory.
        var tlsDir = ntHdr.OptionalHeader.TLSTable;
        if (tlsDir.Size > 0)
        {
            byte[] tlsBytes = new byte[Marshal.SizeOf<IMAGE_TLS_DIRECTORY64>()];
            uint readSize = Math.Min(tlsDir.Size, (uint)Marshal.SizeOf<IMAGE_TLS_DIRECTORY64>());
            if (RPM(FImageBase + tlsDir.VirtualAddress, tlsBytes, readSize))
            {
                var tls = PEHeader.MarshalBytesToStruct<IMAGE_TLS_DIRECTORY64>(tlsBytes);
                long tlsDist = (long)(FImageBase + tlsDir.VirtualAddress) - (long)tls.AddressOfCallBacks;
                if (tlsDist > 0 && tlsDist <= Marshal.SizeOf<IntPtr>() * 5)
                {
                    FTLSTotal = (int)(tlsDist / Marshal.SizeOf<IntPtr>()) - 1;
                    Utils.Log(LogType.Info, $"[MSVC] Expecting {FTLSTotal} TLS entries");
                }
            }
        }
    }

    private void InstallCodeSectionGuard()
    {
        FGuardStart = FImageBase + FPESections[0].VirtualAddress;
        FGuardEnd = FImageBase + FBaseOfData;
        Native.VirtualProtectEx(FProcess.hProcess, (IntPtr)FGuardStart,
            (nuint)(FGuardEnd - FGuardStart), Native.PAGE_NOACCESS, out _);
    }

    private bool IsGuardedAddress(ulong address)
    {
        if (FGuardStart == 0) return false;
        return address >= FGuardStart && address < FGuardEnd;
    }

    private uint ProcessGuardedAccess(IntPtr hThread, ref EXCEPTION_RECORD excRec)
    {
        ulong flag = (ulong)excRec.ExceptionInformation0;
        ulong faultAddr = (ulong)excRec.ExceptionInformation1;
        ulong excAddr = (ulong)excRec.ExceptionAddress;

        Utils.Log(LogType.Info, $"[Guard] {Utils.AccessViolationFlagToStr((byte)flag)} 0x{faultAddr:X}");

        Native.VirtualProtectEx(FProcess.hProcess, (IntPtr)FGuardStart,
            (nuint)(FGuardEnd - FGuardStart), Native.PAGE_EXECUTE_READWRITE, out _);

        if (FTMGuard)
        {
            // We've hit the Themida section after executing a TLS entrypoint.
            FTMGuard = false;
            InstallCodeSectionGuard();
        }
        else if (!InImageBounds(excAddr))
        {
            // Random library code reading our text base...
            FGuardStepping = true;
        }
        else if (excAddr > FGuardEnd)
        {
            // Themida access
            if (TMSectR.Address == 0)
                SelectThemidaSection(excAddr);

            FGuardAddrs.Add(faultAddr);
            FGuardStepping = true;
        }
        else if (flag == 8 && FTLSTotal > 0 && FTLSCounter < FTLSTotal)
        {
            FTLSCounter++;
            Utils.Log(LogType.Good, $"TLS {FTLSCounter}: 0x{excAddr:X8}");
            FGuardStart = TMSectR.Address;
            FGuardEnd = FImageBoundary;
            FTMGuard = true;
            // Allow R/W, disallow execute.
            Native.VirtualProtectEx(FProcess.hProcess, (IntPtr)FGuardStart,
                (nuint)(FGuardEnd - FGuardStart), Native.PAGE_READWRITE, out _);
        }
        else if (FTraceMSVCOEP)
        {
            // We're at mainCrtStartup.
            WriteMSVCOEP(excAddr);
            FinishUnpacking(FMSVCOEP);
        }
        else
        {
            ulong oep = excAddr;

            // Check if virtualized (but goes to .text first for jmp).
            CheckVirtualizedOEP(oep);

            // Check if virtualized and stolen (goes straight into VM without using jmp in .text).
            var c = new CONTEXT();
            c.ContextFlags = Native.CONTEXT_CONTROL;
            if (Native.GetThreadContext(hThread, ref c))
            {
                byte[] retBuf = new byte[8];
                ulong retAddr = 0;
                if (RPM(c.Rsp, retBuf, 8))
                    retAddr = BitConverter.ToUInt64(retBuf, 0);

                if (TMSectR.Contains(retAddr))
                {
                    Utils.Log(LogType.Info, $"Return address points into Themida section: 0x{retAddr:X9}");
                    oep = TryFindCorrectOEP(oep);

                    if (FTraceMSVCOEP)
                    {
                        FMSVCOEP = oep;

                        // Skip and wait for next .text hit.
                        c.Rip = retAddr;
                        c.Rsp += 8;
                        if (!Native.SetThreadContext(hThread, ref c))
                            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

                        InstallCodeSectionGuard();
                        return Native.DBG_CONTINUE;
                    }
                }
                else
                    Utils.Log(LogType.Good, $"OEP: 0x{oep:X8}");
            }
            else
                Utils.Log(LogType.Fatal, "GetThreadContext failed for further OEP check");

            FinishUnpacking(oep);
        }

        if (FGuardStepping)
        {
            // Single-step, then re-protect in OnSinglestep.
            var c = new CONTEXT();
            c.ContextFlags = Native.CONTEXT_CONTROL;
            if (!Native.GetThreadContext(hThread, ref c))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            c.EFlags |= 0x100;
            Native.SetThreadContext(hThread, ref c);
        }

        return Native.DBG_CONTINUE;
    }

    private ulong TryFindCorrectOEP(ulong hitAddress)
    {
        if (FMajorLinkerVersion is not (9 or 10 or 11 or 12 or 14))
        {
            Utils.Log(LogType.Fatal, "Don't know what to do about OEP for this compiler. Your target likely won't run.");
            return hitAddress;
        }

        // MSVC: Assume HitAddress is at __security_init_cookie.
        // Scan for call __security_init_cookie; jmp __scrt_common_main_seh
        ulong textLen = FBaseOfData - FPESections[0].VirtualAddress;
        var textBuf = new byte[textLen];
        if (!RPM(FImageBase + FPESections[0].VirtualAddress, textBuf, textLen))
            throw new Exception("TryFindCorrectOEP: RPM of .text failed");

        ulong scanFor = hitAddress - FImageBase - FPESections[0].VirtualAddress;
        for (ulong i = 0; i + 10 <= textLen; i++)
        {
            if (textBuf[i] == 0xE8 && textBuf[i + 5] == 0xE9 &&
                (uint)(BitConverter.ToInt32(textBuf, (int)(i + 1)) + (long)i + 5) == scanFor)
            {
                ulong oep = FImageBase + FPESections[0].VirtualAddress + i;
                Utils.Log(LogType.Good, $"Found suitable real OEP 0x{oep:X9}");
                return oep;
            }
        }

        // Got two suspicious reads as last accesses, checking out the VM jmp at OEP?
        if (FGuardAddrs.Count >= 2 && FGuardAddrs[^1] == FGuardAddrs[^2] + 1)
        {
            FMSVCInitCookie = hitAddress;
            FTraceMSVCOEP = true;
            return FGuardAddrs[^2];
        }

        Utils.Log(LogType.Fatal, "Real OEP not found. Your target likely won't run.");
        return hitAddress;
    }

    private void WriteMSVCOEP(ulong crtStartup)
    {
        Native.VirtualProtectEx(FProcess.hProcess, (IntPtr)FMSVCOEP, 22, Native.PAGE_EXECUTE_READWRITE, out _);

        var instrs = new byte[22];
        // sub rsp, 0x28
        instrs[0] = 0x48; instrs[1] = 0x83; instrs[2] = 0xEC; instrs[3] = 0x28;
        // call __security_init_cookie
        instrs[4] = 0xE8;
        int callRel = (int)(FMSVCInitCookie - (FMSVCOEP + 4) - 5);
        BitConverter.GetBytes(callRel).CopyTo(instrs, 5);
        // add rsp, 0x28
        instrs[9] = 0x48; instrs[10] = 0x83; instrs[11] = 0xC4; instrs[12] = 0x28;
        // jmp CRTStartup
        instrs[13] = 0xE9;
        int jmpRel = (int)(crtStartup - (FMSVCOEP + 13) - 5);
        BitConverter.GetBytes(jmpRel).CopyTo(instrs, 14);

        if (!Native.WriteProcessMemory(FProcess.hProcess, (IntPtr)FMSVCOEP, instrs, 22, out _))
            throw new Exception($"WriteMSVCOEP failed: {Marshal.GetLastWin32Error()}");

        Utils.Log(LogType.Good, $"Virtualized MSVC9+ OEP restored: 0x{FMSVCOEP:X}");
    }

    private void FinishUnpacking(ulong oep)
    {
        using var dumper = new Dumper(FProcess, FExecutable, FImageBase, oep);

        // Look for IAT by analyzing code near OEP.
        ulong iat = DetermineIATAddress(oep, dumper);
        Utils.Log(LogType.Good, $"IAT: 0x{iat:X8}");

        TraceImports(iat, dumper);

        // Process the IAT into an import directory and dump the binary to disk.
        string fn = Path.Combine(Path.GetDirectoryName(FExecutable)!,
            Path.GetFileNameWithoutExtension(FExecutable) + "U" + Path.GetExtension(FExecutable));
        dumper.IAT = iat;
        dumper.DumpToFile(fn, dumper.Process(), FIsDLL);

        FHideThreadEnd = true;
        Native.TerminateProcess(FProcess.hProcess, 0);

        Utils.Log(LogType.Good, "Operation completed successfully.");
    }

    protected override bool TraceIsAtAPI(Tracer tracer, ref CONTEXT c)
    {
        if (tracer.Counter > 100 && tracer.Counter < 5000)
        {
            byte[] insnData = new byte[4];
            if (RPM(c.Rip, insnData, 4))
            {
                if (BitConverter.ToUInt32(insnData, 0) == 0x0CB10FF0) // "lock cmpxchg [rbx+rbp], ecx"
                {
                    FTraceInVM = true;
                    Utils.Log(LogType.Info, "Trace ran into Themida VM, stopping");
                    return true;
                }
            }
        }

        // cat & mouse game with fake calls
        if (c.Rsp < FTraceStartSP && (c.Rip == FSleepAPI || c.Rip == FlstrlenAPI))
        {
            Utils.Log(LogType.Info, $"Skipping anti-trace API at 0x{c.Rip:X}");
            byte[] retBuf = new byte[8];
            if (RPM(c.Rsp, retBuf, 8))
            {
                ulong returnAddr = BitConverter.ToUInt64(retBuf, 0);
                c.Rsp += 8;
                c.Rip = returnAddr;
            }
        }

        bool result = !TMSectR.Contains(c.Rip);
        if (result && c.Rsp < FTraceStartSP)
        {
            Utils.Log(LogType.Info, $"Warning: Might have encountered new fake API at 0x{c.Rip:X8}");
            result = false;
        }

        if (result)
            FTracedAPI = c.Rip;

        return result;
    }
}