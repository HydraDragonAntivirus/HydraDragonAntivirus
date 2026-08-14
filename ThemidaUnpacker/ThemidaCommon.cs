namespace ThemidaUnpacker;

/// <summary>
/// Port of Magicmida's TTMCommon: shared Themida v3 unpacking helpers used by the
/// x64 debugger (IAT location + import tracing).
/// </summary>
public abstract class ThemidaCommon : DebuggerCore
{
    protected bool FCreateDataSections;
    protected ulong FBaseOfData;
    protected ulong FImageBoundary;
    protected List<IMAGE_SECTION_HEADER> FPESections = new();
    protected byte FMajorLinkerVersion;

    protected byte[] TMSect;         // copy of the Themida section bytes
    protected MemoryRegion TMSectR;  // address/size of the Themida section

    protected bool FThemidaV3 = true;
    protected bool FIsVMOEP;

    protected List<ulong> FGuardAddrs = new();

    // Used by TraceIsAtAPI.
    protected ulong FTracedAPI;
    protected ulong FSleepAPI, FlstrlenAPI;
    protected ulong FTraceStartSP;
    protected bool FTraceInVM;

    protected ThemidaCommon(string executable, string parameters)
        : base(executable, parameters)
    {
    }

    protected ThemidaCommon(uint pid)
        : base(pid)
    {
    }

    protected void InitPEDetails(byte[] header)
    {
        uint lfanew = BitConverter.ToUInt32(header, 0x3C);
        var nt = new byte[24 + 224];
        Array.Copy(header, (int)lfanew, nt, 0, nt.Length);
        var ntheaders = PEHeader.MarshalBytesToStruct<IMAGE_NT_HEADERS64>(nt);

        int numSections = ntheaders.FileHeader.NumberOfSections;
        int secOff = (int)lfanew + 24 + ntheaders.FileHeader.SizeOfOptionalHeader;
        FPESections.Clear();
        for (int i = 0; i < numSections; i++)
        {
            var shBytes = new byte[MarshalSizeSection()];
            Array.Copy(header, secOff, shBytes, 0, shBytes.Length);
            FPESections.Add(PEHeader.MarshalBytesToStruct<IMAGE_SECTION_HEADER>(shBytes));
            secOff += shBytes.Length;
        }

        if (ntheaders.OptionalHeader.AddressOfEntryPoint <
            FPESections[0].VirtualAddress + FPESections[0].VirtualSize)
            throw new Exception("The selected binary does not seem to be packed (entrypoint is in .text section).");

        FImageBoundary = ntheaders.OptionalHeader.SizeOfImage + FImageBase;
        Utils.Log(LogType.Info, $"Image boundary: 0x{FImageBoundary:X}");

        FMajorLinkerVersion = ntheaders.OptionalHeader.MajorLinkerVersion;
        Utils.Log(LogType.Info, $"Image linker: {FMajorLinkerVersion}.{ntheaders.OptionalHeader.MinorLinkerVersion}");
    }

    private static int MarshalSizeSection()
    {
        return System.Runtime.InteropServices.Marshal.SizeOf<IMAGE_SECTION_HEADER>();
    }

    /// <summary>Checks if the OEP at OEP is a jmp into the Themida section (virtualized OEP).</summary>
    protected void CheckVirtualizedOEP(ulong oep)
    {
        byte[] code = new byte[5];
        if (!RPM(oep, code, 5)) return;
        if (code[0] != 0xE9) return;

        uint displ = BitConverter.ToUInt32(code, 1);
        ulong target = oep + 5 + displ;
        if (target < TMSectR.Address) return;

        FIsVMOEP = true;
        Utils.Log(LogType.Info, $"OEP is virtualized (!): jmp 0x{target:X}");
    }

    /// <summary>
    /// Scans the code section for a call/jmp qword ptr [rip+disp32], returning the
    /// address of the IAT slot referenced (port of DetermineIATAddress).
    /// </summary>
    protected ulong DetermineIATAddress(ulong oep, Dumper dumper)
    {
        // For MSVC, the IAT often resides at FImageBase + FBaseOfData.
        int dataSectionIndex = 0;
        for (int si = 0; si < FPESections.Count; si++)
            if (FBaseOfData < FPESections[si].VirtualAddress + FPESections[si].VirtualSize)
            {
                dataSectionIndex = si;
                break;
            }

        ulong textBase = FImageBase + FPESections[0].VirtualAddress;
        ulong codeSize = FBaseOfData - FPESections[0].VirtualAddress;
        ulong dataSize = FPESections[dataSectionIndex].VirtualSize -
                         (FBaseOfData - FPESections[dataSectionIndex].VirtualAddress);
        Utils.Log(LogType.Info, $"Text base: 0x{textBase:X8}, code size: 0x{codeSize:X}, data size: 0x{dataSize:X}");

        var codeDump = new byte[codeSize];
        if (!RPM(textBase, codeDump, codeSize))
            throw new Exception("DetermineIATAddress: RPM failed");

        ulong iatRef = 0;

        if (codeDump.Length >= 4 && BitConverter.ToUInt32(codeDump, 0) == 0x6F4720FF)
            iatRef = FindGoAPICall(textBase + FindGoBuildIdEnd(codeDump, codeSize), textBase, codeSize, codeDump, dumper);
        else if (!FIsVMOEP)
            iatRef = FindCallOrJmpPtr(oep, textBase, codeSize, codeDump, false);
        else if (codeDump.Length >= 14 &&
                 (BitConverter.ToUInt32(codeDump, 10) == 0x6C6F6F42 || BitConverter.ToUInt32(codeDump, 6) == 0x65747942))
            iatRef = FindCallOrJmpPtr(textBase + FindDelphiCall(codeDump, codeSize), textBase, codeSize, codeDump, true);
        else
            iatRef = FindCallOrJmpPtr(textBase, textBase, codeSize, codeDump, true);

        if (iatRef == 0)
        {
            Utils.Log(LogType.Info, "No IAT reference found via reference search");
            if (FGuardAddrs.Count > 0)
            {
                byte[] site = new byte[6];
                ulong target;
                if (!RPM(FGuardAddrs[0], site, 6))
                    throw new Exception("RPM of guard addr failed");

                if (site[0] == 0xE8 || site[0] == 0xE9)
                    target = BitConverter.ToUInt32(site, 1) + FGuardAddrs[0] + 5;
                else if (site[1] == 0xE8 || site[1] == 0xE9)
                    target = BitConverter.ToUInt32(site, 2) + FGuardAddrs[0] + 6;
                else
                    throw new Exception("First guard addr is not call/jmp");

                Utils.Log(LogType.Info, $"First guard addr 0x{FGuardAddrs[0]:X8} yielded API 0x{target:X8}");
                iatRef = ScanData(target, textBase, codeSize, dataSize, dumper, true);
            }
            else
                throw new Exception("Found no way to obtain IAT reference");
        }
        Utils.Log(LogType.Good, $"First IAT ref: 0x{iatRef:X8}");

        // Now walk backwards from IATRef to find the start of the table.
        ulong result = 0;
        ulong seeker = iatRef;
        uint bufferSize = DumperConst.MAX_IAT_SIZE;
        ulong readStart = iatRef - (bufferSize - 8);
        var iatData = new byte[bufferSize];
        if (!RPM(readStart, iatData, bufferSize))
            throw new Exception("RPM of IAT data failed");

        int consecutive0 = 0;
        int i = (int)(bufferSize / 8) - 1;
        while (i >= 0)
        {
            ulong value = BitConverter.ToUInt64(iatData, i * 8);
            if (value == 0)
            {
                consecutive0++;
                if (consecutive0 > 64)
                    break;
            }
            else if (dumper.IsAPIAddress(value) || (FThemidaV3 && TMSectR.Contains(value)))
            {
                result = seeker;
                consecutive0 = 0;
            }
            else
            {
                Utils.Log(LogType.Info, $"Ending IAT start search at 0x{seeker:X} because pointer is 0x{value:X}");
                break;
            }

            i--;
            seeker -= 8;
        }
        if (i == -1)
            throw new Exception("IAT too big");

        if (result == 0)
            throw new Exception("IAT assertion failed");

        return result;
    }

    /// <summary>Finds the end of the "Go build ID" string at the start of a Go .text section.</summary>
    private static ulong FindGoBuildIdEnd(byte[] codeDump, ulong codeSize)
    {
        // Go has "Go build ID" at the start of .text. 20 FF marks the end.
        for (int i = 0; (ulong)i < codeSize - 2; i++)
            if (codeDump[i] == 0xFF && codeDump[i + 1] == 0x20)
                return (ulong)i + 2;
        return 0;
    }

    /// <summary>Delphi has type metadata at its .text base; finds the third FF25 (jmp ptr) entry.</summary>
    private static ulong FindDelphiCall(byte[] codeDump, ulong codeSize)
    {
        int counter = 0;
        for (int i = 0; (ulong)i < codeSize - 6; i++)
        {
            if (codeDump[i] == 0xFF && codeDump[i + 1] == 0x25)
            {
                counter++;
                if (counter == 3)
                    return (ulong)i;
            }
        }
        return 0;
    }

    /// <summary>Scan a region of the image for the first occurrence of a machine-word ToFind.</summary>
    private static ulong ScanData(ulong toFind, ulong textBase, ulong codeSize, ulong dataSize, Dumper dumper, bool scanCode)
    {
        ulong startOffset = scanCode ? textBase : textBase + codeSize;
        ulong scanSize = scanCode ? codeSize : dataSize;

        var dataSect = new byte[scanSize];
        if (!dumper.ReadRegion(startOffset, dataSect, scanSize))
            throw new Exception("DetermineIATAddress.ScanData: RPM failed");

        // Word-aligned scan.
        for (ulong off = 0; off + 8 <= scanSize; off += 8)
        {
            if (BitConverter.ToUInt64(dataSect, (int)off) == toFind)
                return off + startOffset;
        }

        if (scanCode)
            throw new Exception("Unable to find API in section");
        return ScanData(toFind, textBase, codeSize, dataSize, dumper, true);
    }

    /// <summary>
    /// Walks the instruction stream from Address looking for a call/jmp qword ptr
    /// [rip+disp32]; returns the target of that memory operand (the IAT slot address).
    /// </summary>
    private ulong FindCallOrJmpPtr(ulong address, ulong textBase, ulong codeSize, byte[] codeDump, bool ignoreMethodBoundary)
    {
        ulong result = 0;
        int numInstr = 0;
        ulong addr = address;

        while (numInstr < 200 || (ignoreMethodBoundary && addr < textBase + codeSize))
        {
            if (addr < textBase || addr >= textBase + (ulong)codeDump.Length)
                break;

            int off = (int)(addr - textBase);
            var insn = Disasm.Decode(codeDump, off, codeDump.Length, addr);

            if (insn.Kind == X64InsnKind.CallPtr || insn.Kind == X64InsnKind.JmpPtr)
            {
                Utils.Log(LogType.Info, $"Found 0x{addr:X} : call/jmp ptr to 0x{insn.RipDisp:X}");
                ulong iatPointer = insn.RipDisp;
                // Ensure we didn't stumble upon a pointer into .text.
                byte[] ptrBuf = new byte[8];
                ulong thePointer = 0;
                if (!RPM(iatPointer, ptrBuf, 8))
                    return iatPointer;
                thePointer = BitConverter.ToUInt64(ptrBuf, 0);
                if (thePointer > textBase + codeSize)
                    return iatPointer;
            }

            if (insn.Kind == X64InsnKind.CallRel && !ignoreMethodBoundary)
            {
                if (insn.RelTarget < textBase || insn.RelTarget > textBase + codeSize)
                    return 0; // Direct API call.
                result = FindCallOrJmpPtr(insn.RelTarget, textBase, codeSize, codeDump, false);
                if (result != 0)
                    return result;
            }

            if (insn.Kind == X64InsnKind.Ret && !ignoreMethodBoundary)
                return 0;

            numInstr++;
            if (insn.Length > 0)
                addr += (ulong)insn.Length;
            else
                addr++;
        }
        return 0;
    }

    /// <summary>Go-style: mov rax,[rip+disp]; mov [rsp],rax - returns IAT slot address.</summary>
    private ulong FindGoAPICall(ulong address, ulong textBase, ulong codeSize, byte[] codeDump, Dumper dumper)
    {
        ulong addr = address;
        while (addr < textBase + codeSize)
        {
            if (addr < textBase || addr >= textBase + (ulong)codeDump.Length)
                break;

            int off = (int)(addr - textBase);
            var insn = Disasm.Decode(codeDump, off, codeDump.Length, addr);

            // mov rax,[rip+disp] then mov [rsp],rax  (len 7 + next 4 bytes 48 89 04 24)
            if (insn.Kind == X64InsnKind.MovRaxPtr && insn.Length == 7 && off + 7 + 4 <= codeDump.Length)
            {
                if (BitConverter.ToUInt32(codeDump, off + 7) == 0x24048948)
                {
                    ulong iatPointer = insn.RipDisp;
                    byte[] ptrBuf = new byte[8];
                    if (RPM(iatPointer, ptrBuf, 8) &&
                        dumper.IsAPIAddress(BitConverter.ToUInt64(ptrBuf, 0)))
                        return iatPointer;
                }
            }

            if (insn.Length > 0)
                addr += (ulong)insn.Length;
            else
                addr++;
        }
        return 0;
    }

    /// <summary>
    /// Traces each IAT slot that points into the Themida section to resolve the real API
    /// it jumps to, writing the resolved pointers back into the process IAT.
    /// </summary>
    protected void TraceImports(ulong iat, Dumper dumper)
    {
        var iatData = new byte[DumperConst.MAX_IAT_SIZE];
        if (!RPM(iat, iatData, DumperConst.MAX_IAT_SIZE))
            throw new Exception("TraceImports: RPM of IAT failed");

        bool didSetExitProcess = false;
        int trashCounter = 0;
        int slotCount = DumperConst.MAX_IAT_SIZE / 8;

        for (int i = 0; i < slotCount; i++)
        {
            ulong slotValue = BitConverter.ToUInt64(iatData, i * 8);

            if (TMSectR.Contains(slotValue))
            {
                Utils.Log(LogType.Info, $"Trace: 0x{slotValue:X8} [0x{iat + (ulong)i * 8:X8}]");

                trashCounter = 0;

                var ctx = new CONTEXT();
                ctx.ContextFlags = Native.CONTEXT_CONTROL;
                Native.GetThreadContext(GetThread(FCurrentThreadID), ref ctx);
                FTraceStartSP = ctx.Rsp;

                FTracedAPI = 0;
                FTraceInVM = false;

                using (var tracer = new Tracer(FProcess.dwProcessId, FCurrentThreadID, GetThread(FCurrentThreadID), TraceIsAtAPI))
                {
                    // Normally a couple hundred suffice, but newer Themida v3 versions
                    // do some export directory walking...
                    tracer.Trace(slotValue, 500000);

                    if (FTraceInVM)
                    {
                        if (!didSetExitProcess)
                        {
                            didSetExitProcess = true;
                            // ExitProcess resolves to a VM func - assume only one such case.
                            slotValue = (ulong)Native.GetProcAddress(Native.GetModuleHandle("kernel32.dll"), "ExitProcess");
                            Utils.Log(LogType.Info, "Setting API to ExitProcess");
                        }
                        else
                            Utils.Log(LogType.Fatal, $"Unable to determine IAT address for 0x{iat + (ulong)i * 8:X8}");
                    }
                    else if (FTracedAPI != 0)
                    {
                        Utils.Log(LogType.Info, $"-> 0x{FTracedAPI:X8}");
                        if (FTracedAPI < 0x10000 ||
                            (FTracedAPI >= FImageBase && FTracedAPI < FImageBoundary))
                        {
                            Utils.Log(LogType.Info, "Discarding result & aborting IAT tracing");
                            break;
                        }
                        slotValue = FTracedAPI;
                    }
                    else
                        Utils.Log(LogType.Fatal, "Tracing failed!");
                }

                BitConverter.GetBytes(slotValue).CopyTo(iatData, i * 8);
            }
            else if (slotValue == 0 || !dumper.IsAPIAddress(slotValue))
            {
                trashCounter++;
                if (trashCounter > 64)
                    break;
            }
            else
                trashCounter = 0;
        }

        Native.VirtualProtectEx(FProcess.hProcess, (IntPtr)iat, DumperConst.MAX_IAT_SIZE, Native.PAGE_READWRITE, out _);
        if (!Native.WriteProcessMemory(FProcess.hProcess, (IntPtr)iat, iatData, DumperConst.MAX_IAT_SIZE, out _))
            throw new System.ComponentModel.Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
    }

    /// <summary>Called by the Tracer on every single step. Returns true to stop tracing.</summary>
    protected abstract bool TraceIsAtAPI(Tracer tracer, ref CONTEXT c);
}
