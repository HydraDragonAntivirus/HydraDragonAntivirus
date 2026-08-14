using System.Runtime.InteropServices;

namespace ThemidaUnpacker;

public static class DumperConst
{
    public const int MAX_IAT_SIZE = 5120 * 8; // 5K imports * ptrsize (64-bit)
}

public class Forward
{
    public string Key;
    public ulong Value;

    public Forward(string key, ulong value)
    {
        Key = key;
        Value = value;
    }
}

public class RemoteModule
{
    public ulong Base;
    public ulong EndOff;
    public string Name;
    public Dictionary<ulong, string> ExportTbl = new();
    public List<Forward> Forwards = new();
}

public class ForwardOrigin
{
    public RemoteModule SourceModule;
    public ulong SourceAddress;

    public ForwardOrigin(RemoteModule mod, ulong addr)
    {
        SourceModule = mod;
        SourceAddress = addr;
    }
}

public class ImportThunk
{
    public RemoteModule Module;
    public string Name;
    public List<ulong> Addresses = new();

    public ImportThunk(RemoteModule rm)
    {
        Module = rm;
        Name = rm.Name;
    }
}

public struct OriginalImport
{
    public string DLLName;
    public string FuncName;
}

/// <summary>
/// Port of Magicmida's TDumper. Dumps the unpacked process and rebuilds
/// the import table from the resolved IAT.
/// </summary>
public class Dumper : IDisposable
{
    private readonly PROCESS_INFORMATION FProcess;
    private readonly ulong FOEP;
    private ulong FIAT;
    private readonly ulong FImageBase;

    private readonly Dictionary<ulong, List<ForwardOrigin>> FForwards = new();
    private List<RemoteModule> FAllModules;
    private byte[] FIATImage;
    private uint FIATImageSize;
    private readonly List<OriginalImport> FOriginalImports;

    private static readonly string[] ForwardPreferences =
    {
        "kernel32.dll", "ole32.dll", "advapi32.dll", "netapi32.dll", "comdlg32.dll",
        "crypt32.dll", "gdi32.dll", "dbghelp.dll", "setupapi.dll"
    };

    public ulong IAT
    {
        get => FIAT;
        set => FIAT = value;
    }

    public Dumper(PROCESS_INFORMATION process, string originalFile, ulong imageBase, ulong oep)
    {
        FProcess = process;
        FOEP = oep;
        FImageBase = imageBase;

        FOriginalImports = GetOriginalImports(originalFile);
    }

    public void Dispose()
    {
        if (FAllModules != null)
        {
            foreach (var rm in FAllModules)
            {
                rm.ExportTbl.Clear();
                rm.Forwards.Clear();
            }
            FAllModules.Clear();
        }
        FForwards.Clear();
        FOriginalImports.Clear();
    }

    private static int PreferenceScore(string name)
    {
        int score = 0;
        foreach (var p in ForwardPreferences)
            if (string.Equals(name, p, StringComparison.OrdinalIgnoreCase))
                score++;
        return score;
    }

    private bool RPM(ulong address, byte[] buf, ulong size)
    {
        return Native.ReadProcessMemory(FProcess.hProcess, (IntPtr)address, buf, (nuint)size, out _);
    }

    /// <summary>RPM that is accessible from ThemidaCommon for region scanning.</summary>
    public bool ReadRegion(ulong address, byte[] buf, ulong size)
    {
        return RPM(address, buf, size);
    }

    /// <summary>Determines the physical size of the IAT (last valid entry + ptr).</summary>
    public uint DetermineIATSize(byte[] iat)
    {
        uint lastValidOffset = 0;
        uint i = 0;
        while (i < DumperConst.MAX_IAT_SIZE && (lastValidOffset == 0 || i < lastValidOffset + 0x100))
        {
            if (IsAPIAddress(BitConverter.ToUInt64(iat, (int)i)))
                lastValidOffset = i;
            i += 8;
        }
        return lastValidOffset + 8;
    }

    public bool IsAPIAddress(ulong address)
    {
        if (FAllModules == null)
            TakeModuleSnapshot();

        foreach (var rm in FAllModules)
            if (address >= rm.Base && address < rm.EndOff)
                return rm.ExportTbl.ContainsKey(address);

        return false;
    }

    /// <summary>Reads the image from the process, builds a new import section and returns the rebuilt PE.</summary>
    public PEHeader Process()
    {
        if (FIAT == 0)
            throw new Exception("Must set IAT before calling Process()");

        // Read header from memory
        var headerBuf = new byte[0x1000];
        RPM(FImageBase, headerBuf, 0x1000);
        var PE = new PEHeader(headerBuf);
        PE.Sanitize();
        PE.NTHeaders.FileHeader.NumberOfSections = (ushort)PE.Sections.Count;

        var iat = new byte[DumperConst.MAX_IAT_SIZE];
        RPM(FIAT, iat, DumperConst.MAX_IAT_SIZE);

        uint iatSize = DetermineIATSize(iat);
        Utils.Log(LogType.Info, $"Determined IAT size: {iatSize:X}");

        PE.NTHeaders.OptionalHeader.IAT.VirtualAddress = (uint)(FIAT - FImageBase);
        PE.NTHeaders.OptionalHeader.IAT.Size = iatSize + 8;

        if (FAllModules == null)
            TakeModuleSnapshot();

        bool allowApiSets = false;
        foreach (var oi in FOriginalImports)
            if (oi.DLLName.StartsWith("api-ms-win"))
            {
                allowApiSets = true;
                break;
            }

        int slotCount = (int)(iatSize / 8);
        var slots = new List<IATSlot>(slotCount);

        // --- PASS 1: collect all candidates for every IAT slot ---
        for (int i = 0; i < slotCount; i++)
        {
            var slot = new IATSlot { ChosenCandidate = -1 };
            slot.Candidates = new List<ResolutionCandidate>();
            ulong ptr = BitConverter.ToUInt64(iat, i * 8);
            slot.IsZero = ptr == 0;

            if (slot.IsZero)
                continue;

            // Variant A: no forwarding
            foreach (var rm in FAllModules)
            {
                if (ptr > rm.Base && ptr < rm.EndOff)
                {
                    if (rm.ExportTbl.ContainsKey(ptr))
                        slot.Candidates.Add(new ResolutionCandidate { Address = ptr, Module = rm });
                    break;
                }
            }

            // Variant B: forwards
            if (FForwards.TryGetValue(ptr, out var origins))
            {
                foreach (var origin in origins)
                    slot.Candidates.Add(new ResolutionCandidate { Address = origin.SourceAddress, Module = origin.SourceModule });
            }

            if (slot.Candidates.Count == 0)
                Utils.Log(LogType.Info, $"IAT slot 0x{FIAT + (ulong)i * 8:X} -> 0x{ptr:X} unresolvable");

            slots.Add(slot);
        }

        // --- PASS 2: group by zero-separator, vote on best module ---
        var thunks = new List<ImportThunk>();
        int idx = 0;
        while (idx < slots.Count)
        {
            if (slots[idx].IsZero) { idx++; continue; }

            // Find contiguous non-zero run
            int groupStart = idx;
            int groupEnd = idx;
            while (groupEnd + 1 < slots.Count && !slots[groupEnd + 1].IsZero)
                groupEnd++;

            // Vote
            var moduleVotes = new Dictionary<string, int>();
            for (int j = groupStart; j <= groupEnd; j++)
            {
                foreach (var cand in slots[j].Candidates)
                {
                    string modName = cand.Module.Name;
                    if (!moduleVotes.TryGetValue(modName, out int votes))
                        moduleVotes[modName] = 1;
                    else
                        moduleVotes[modName] = votes + 1;
                }
            }

            // Winner
            string winnerName = "";
            int winnerVotes = -1;
            RemoteModule winnerRM = null;
            foreach (var kv in moduleVotes)
            {
                if (kv.Value > winnerVotes ||
                    (kv.Value == winnerVotes && PreferenceScore(kv.Key) > PreferenceScore(winnerName)))
                {
                    winnerVotes = kv.Value;
                    winnerName = kv.Key;
                }
            }

            // Pin each slot to winning module's candidate
            for (int j = groupStart; j <= groupEnd; j++)
            {
                for (int k = 0; k < slots[j].Candidates.Count; k++)
                {
                    if (slots[j].Candidates[k].Module.Name == winnerName)
                    {
                        slots[j].ChosenCandidate = k;
                        if (winnerRM == null)
                            winnerRM = slots[j].Candidates[k].Module;
                        break;
                    }
                }
            }

            // Build thunk
            ImportThunk thunk = null;
            for (int j = groupStart; j <= groupEnd; j++)
            {
                if (slots[j].ChosenCandidate < 0)
                {
                    Utils.Log(LogType.Fatal, $"IAT slot 0x{FIAT + (ulong)j * 8:X} has no candidate for winning module {winnerName}");
                    continue;
                }

                if (thunk == null)
                {
                    thunk = new ImportThunk(winnerRM) { Name = winnerName };
                    thunks.Add(thunk);
                }

                var cand = slots[j].Candidates[slots[j].ChosenCandidate];
                ulong slotAddr = FIAT + (ulong)j * 8;
                WriteUInt64(slotAddr, cand.Address);
                thunk.Addresses.Add(slotAddr);
            }

            idx = groupEnd + 1;
        }

        // --- Build import section ---
        var importSect = PE.CreateSection(".import", 0x1000);
        var importData = new byte[importSect.Header.SizeOfRawData];
        int descriptorsSize = (thunks.Count + 1) * Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>();
        int strOffset = descriptorsSize;

        for (int i = 0; i < thunks.Count; i++)
        {
            var thunk = thunks[i];
            var desc = new IMAGE_IMPORT_DESCRIPTOR();
            desc.FirstThunk = (uint)((FIAT - FImageBase) + thunk.Addresses[0] - FIAT);
            desc.Name = (uint)PE.ConvertOffsetToRVAVector((ulong)(importSect.Header.PointerToRawData + (uint)strOffset));

            // Write DLL name
            byte[] nameBytes = System.Text.Encoding.ASCII.GetBytes(thunk.Name);
            Array.Copy(nameBytes, 0, importData, strOffset, nameBytes.Length);
            strOffset += nameBytes.Length + 1;

            var rm = thunk.Module;
            Utils.Log(LogType.Info, $"Thunk {thunk.Name} - first import: {rm.ExportTbl[(ulong)thunk.Addresses[0]]}");

            foreach (var addr in thunk.Addresses)
            {
                string s = rm.ExportTbl[addr];
                if (s.StartsWith("#"))
                {
                    uint ordIndex = uint.Parse(s.Substring(1, 5));
                    WriteUInt64(addr, Native.IMAGE_ORDINAL_FLAG64 | ordIndex);
                    continue;
                }

                strOffset += 2; // Hint
                ulong hintRva = PE.ConvertOffsetToRVAVector((ulong)(importSect.Header.PointerToRawData + (uint)(strOffset - 2)));
                WriteUInt64(addr, hintRva);
                byte[] funcBytes = System.Text.Encoding.ASCII.GetBytes(s);
                Array.Copy(funcBytes, 0, importData, strOffset, funcBytes.Length);
                strOffset += funcBytes.Length + 1;

                if (strOffset > importSect.Header.SizeOfRawData - 0x100)
                {
                    Utils.Log(LogType.Info, "Growing import section");
                    importSect.Header.SizeOfRawData += 0x1000;
                    importSect.Header.VirtualSize += 0x1000;
                    PE.NTHeaders.OptionalHeader.SizeOfImage += 0x1000;
                    Array.Resize(ref importData, (int)importSect.Header.SizeOfRawData);
                }
            }

            // Copy descriptor into importData
            int descOffset = i * Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>();
            var descBytes = PEHeader.StructToBytes(desc);
            Array.Copy(descBytes, 0, importData, descOffset, descBytes.Length);
        }

        importSect.Data = importData;
        PE.NTHeaders.OptionalHeader.ImportTable.VirtualAddress = importSect.Header.VirtualAddress;
        PE.NTHeaders.OptionalHeader.ImportTable.Size = (uint)(thunks.Count * Marshal.SizeOf<IMAGE_IMPORT_DESCRIPTOR>());

        FIATImage = iat;
        FIATImageSize = iatSize;

        return PE;
    }

    private bool WriteUInt64(ulong address, ulong value)
    {
        byte[] buf = new byte[8];
        Array.Copy(PEHeader.StructToBytes(value), 0, buf, 0, 8);
        return Native.WriteProcessMemory(FProcess.hProcess, (IntPtr)address, buf, 8, out _);
    }

    /// <summary>Dumps the process image to a file and writes the rebuilt IAT into it.</summary>
    public void DumpToFile(string fileName, PEHeader pe, bool isDLL = false)
    {
        using var fs = new FileStream(fileName, FileMode.Create, FileAccess.ReadWrite);
        uint size = pe.DumpSize;
        var buf = new byte[size];

        // Make all memory readable (Themida may have NOACCESS regions)
        MakeMemoryReadable(FImageBase, size);

        if (!RPM(FImageBase, buf, size))
            throw new Exception($"DumpToFile RPM failed (base: {FImageBase:X}, size: {size:X})");

        uint iatRawOffset = (uint)(FIAT - FImageBase);
        uint delta = pe.TrimHugeSections(buf, ref iatRawOffset);
        size -= delta;
        fs.Write(buf, 0, (int)size);

        // Write data of any new sections (e.g. .import)
        for (int i = pe.NTHeaders.FileHeader.NumberOfSections; i < pe.Sections.Count; i++)
        {
            if (pe.Sections[i].Data != null)
                fs.Write(pe.Sections[i].Data, 0, (int)pe.Sections[i].Header.SizeOfRawData);
        }
        pe.NTHeaders.FileHeader.NumberOfSections = (ushort)pe.Sections.Count;
        pe.NTHeaders.OptionalHeader.AddressOfEntryPoint = (uint)(FOEP - FImageBase);

        if (isDLL)
        {
            pe.NTHeaders.FileHeader.Characteristics |= (ushort)Native.IMAGE_FILE_DLL;
        }

        if ((pe.NTHeaders.OptionalHeader.DllCharacteristics & 0x40) != 0)
        {
            Utils.Log(LogType.Info, "Executable is ASLR-aware - disabling the flag in the dump");
            pe.NTHeaders.OptionalHeader.DllCharacteristics &= (ushort)0xFFBF;
        }

        // Save NT headers + section headers
        var hdrBytes = pe.ToBytes();
        fs.Seek((int)pe.LFANew, SeekOrigin.Begin);
        fs.Write(hdrBytes, (int)pe.LFANew, hdrBytes.Length - (int)pe.LFANew);

        // Write the rebuilt IAT
        fs.Seek(iatRawOffset, SeekOrigin.Begin);
        fs.Write(FIATImage, 0, (int)FIATImageSize);
    }

    private void MakeMemoryReadable(ulong baseAddr, ulong size)
    {
        ulong addr = baseAddr;
        ulong endAddr = baseAddr + size;
        while (addr < endAddr)
        {
            var mbi = new MEMORY_BASIC_INFORMATION();
            nuint result = Native.VirtualQueryEx(FProcess.hProcess, (IntPtr)addr, out mbi, (nuint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());
            if (result == 0) break;

            if (mbi.State == Native.MEM_COMMIT && mbi.Protect == Native.PAGE_NOACCESS)
                Native.VirtualProtectEx(FProcess.hProcess, mbi.BaseAddress, mbi.RegionSize, Native.PAGE_READWRITE, out _);

            addr = (ulong)mbi.BaseAddress + (ulong)mbi.RegionSize;
        }
    }

    private void GatherModuleExportsFromRemoteProcess(RemoteModule m)
    {
        var head = new byte[0x1000];
        if (!RPM(m.Base, head, 0x1000)) return;

        uint lfanew = BitConverter.ToUInt32(head, 0x3C);
        uint expVA = BitConverter.ToUInt32(head, (int)(lfanew + 24 + 112));
        uint expSize = BitConverter.ToUInt32(head, (int)(lfanew + 24 + 116));
        if (expVA == 0 || expSize < Marshal.SizeOf<IMAGE_EXPORT_DIRECTORY>()) return;

        var exp = new byte[expSize];
        if (!RPM(m.Base + expVA, exp, expSize)) return;
        // Off: buffer start maps to VA expVA
        ulong off = (ulong)(expVA); // delta between buffer ptr and VA

        // NOTE: In the Delphi version, "Off" is used as PByte(Exp) - ExpDataDir.VirtualAddress
        // which is a *negative* delta since Exp is a memory buffer, not mapped VA. We emulate
        // by reading the directory fields with a helper.
        uint numFunctions = BitConverter.ToUInt32(exp, 0x14);
        uint numNames = BitConverter.ToUInt32(exp, 0x18);
        uint baseOrd = BitConverter.ToUInt32(exp, 0x10);
        uint addrOfFunctions = BitConverter.ToUInt32(exp, 0x1C);
        uint addrOfNames = BitConverter.ToUInt32(exp, 0x20);
        uint addrOfNameOrdinals = BitConverter.ToUInt32(exp, 0x24);

        var named = new bool[numFunctions];
        byte[] funcPtrBuf = new byte[4];
        byte[] ordPtrBuf = new byte[2];
        byte[] namePtrBuf = new byte[4];
        byte[] funcAddrBuf = new byte[4];

        for (int i = 0; i < numNames; i++)
        {
            // read o[i] and n[i]
            if (!RPM(m.Base + expVA + addrOfNameOrdinals + (uint)(i * 2), ordPtrBuf, 2)) continue;
            ushort funcIndex = BitConverter.ToUInt16(ordPtrBuf, 0);
            if (funcIndex >= numFunctions) continue;
            if (!RPM(m.Base + expVA + addrOfNames + (uint)(i * 4), namePtrBuf, 4)) continue;
            uint nameRVA = BitConverter.ToUInt32(namePtrBuf, 0);
            if (!RPM(m.Base + expVA + addrOfFunctions + (uint)(funcIndex * 4), funcAddrBuf, 4)) continue;
            uint funcRVA = BitConverter.ToUInt32(funcAddrBuf, 0);

            named[funcIndex] = true;
            string fname = ReadCString(m.Base + nameRVA, 256);
            if (fname.Length > 0)
                m.ExportTbl[m.Base + funcRVA] = fname;
        }

        for (int i = 0; i < numFunctions; i++)
        {
            if (!RPM(m.Base + expVA + addrOfFunctions + (uint)(i * 4), funcAddrBuf, 4)) continue;
            uint funcRVA = BitConverter.ToUInt32(funcAddrBuf, 0);
            ulong funcAddr = m.Base + funcRVA;

            // Add ordinals
            if (i >= named.Length || !named[i])
            {
                uint ordIndex = baseOrd + (uint)i;
                m.ExportTbl[funcAddr] = "#" + ordIndex.ToString();
            }

            // Check if entry is forward (points into the export directory itself)
            if (funcRVA >= expVA && funcRVA < expVA + expSize)
            {
                string fwd = ReadCString(m.Base + funcRVA, 256);
                if (!fwd.Contains(".#"))
                    m.Forwards.Add(new Forward(fwd, funcAddr));
            }
        }
    }

    private string ReadCString(ulong address, int maxLen)
    {
        var buf = new byte[maxLen];
        if (!RPM(address, buf, (nuint)maxLen)) return "";
        int len = 0;
        while (len < maxLen && buf[len] != 0) len++;
        return System.Text.Encoding.ASCII.GetString(buf, 0, len);
    }

    private void ResolveForwards(RemoteModule m)
    {
        foreach (var fwd in m.Forwards)
        {
            int dotPos = fwd.Key.IndexOf('.');
            if (dotPos < 0) continue;
            string forwardModName = fwd.Key.Substring(0, dotPos);
            string forwardAPIName = fwd.Key.Substring(dotPos + 1);

            RemoteModule forwardMod;
            if (forwardModName.Contains("-ms-win-"))
            {
                // api-ms-win, ext-ms-win - resolve locally
                IntPtr h = Native.GetModuleHandle(forwardModName);
                forwardMod = h != IntPtr.Zero ? GetRemoteModule(h) : null;
            }
            else
                forwardMod = GetRemoteModule(forwardModName + ".dll");

            if (forwardMod != null)
            {
                ulong procAddr = 0;
                foreach (var expr in forwardMod.ExportTbl)
                    if (expr.Value == forwardAPIName)
                    {
                        procAddr = expr.Key;
                        break;
                    }

                if (procAddr != 0)
                {
                    if (!FForwards.ContainsKey(procAddr))
                        FForwards[procAddr] = new List<ForwardOrigin>();
                    FForwards[procAddr].Add(new ForwardOrigin(m, fwd.Value));
                }
            }
        }
    }

    private RemoteModule GetRemoteModule(IntPtr baseAddr)
    {
        foreach (var rm in FAllModules)
            if ((IntPtr)rm.Base == baseAddr)
                return rm;
        return null;
    }

    private RemoteModule GetRemoteModule(string name)
    {
        foreach (var rm in FAllModules)
            if (rm.Name == name.ToLowerInvariant())
                return rm;
        return null;
    }

    private void TakeModuleSnapshot()
    {
        FAllModules = new List<RemoteModule>();
        IntPtr hSnap = Native.CreateToolhelp32Snapshot(Native.TH32CS_SNAPMODULE | Native.TH32CS_SNAPMODULE32, FProcess.dwProcessId);
        if (hSnap == IntPtr.Zero) throw new Exception("CreateToolhelp32Snapshot failed");

        var me = new MODULEENTRY32 { dwSize = (uint)Marshal.SizeOf<MODULEENTRY32>() };
        if (!Native.Module32First(hSnap, ref me))
        {
            Native.CloseHandle(hSnap);
            throw new Exception("Module32First failed");
        }

        do
        {
            if ((ulong)me.hModule != FImageBase)
            {
                var rm = new RemoteModule
                {
                    Base = (ulong)me.modBaseAddr,
                    EndOff = (ulong)me.modBaseAddr + me.modBaseSize,
                    Name = me.szModule.ToLowerInvariant(),
                };
                GatherModuleExportsFromRemoteProcess(rm);
                FAllModules.Add(rm);
            }
        } while (Native.Module32Next(hSnap, ref me));

        Native.CloseHandle(hSnap);

        foreach (var rm in FAllModules)
            ResolveForwards(rm);
    }

    private List<OriginalImport> GetOriginalImports(string fileName)
    {
        var result = new List<OriginalImport>();
        try
        {
            var fs = new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var headerBuf = new byte[0x1000];
            fs.Read(headerBuf, 0, headerBuf.Length);
            var filePE = new PEHeader(headerBuf);
            uint importVA = filePE.NTHeaders.OptionalHeader.ImportTable.VirtualAddress;
            uint importSize = filePE.NTHeaders.OptionalHeader.ImportTable.Size;
            if (importVA == 0 || importSize == 0) return result;

            var sect = filePE.GetSectionByVA(importVA);
            if (sect == null) return result;

            var sectBuf = new byte[sect.Header.SizeOfRawData];
            fs.Position = sect.Header.PointerToRawData;
            fs.Read(sectBuf, 0, sectBuf.Length);
            fs.Dispose();

            uint descOff = importVA - sect.Header.VirtualAddress;
            while (descOff + 20 <= sectBuf.Length)
            {
                uint nameRVA = BitConverter.ToUInt32(sectBuf, (int)descOff + 12);
                if (nameRVA == 0) break;

                uint nameOff = nameRVA - sect.Header.VirtualAddress;
                string dllName = ReadCStringAt(sectBuf, (int)nameOff, 256);
                if (dllName.Length == 0) break;

                uint firstThunk = BitConverter.ToUInt32(sectBuf, (int)descOff + 16);
                uint thunkOff = firstThunk - sect.Header.VirtualAddress;
                while (thunkOff + 8 <= sectBuf.Length)
                {
                    ulong thunk = BitConverter.ToUInt64(sectBuf, (int)thunkOff);
                    if (thunk == 0) break;

                    var oi = new OriginalImport { DLLName = dllName.ToLowerInvariant() };
                    if ((thunk & Native.IMAGE_ORDINAL_FLAG64) != 0)
                        oi.FuncName = "#" + (thunk & 0xFFFF).ToString();
                    else
                        oi.FuncName = ReadCStringAt(sectBuf, (int)(thunk - sect.Header.VirtualAddress) + 2, 256);

                    result.Add(oi);
                    thunkOff += 8;
                }

                descOff += 20;
            }
        }
        catch { }
        return result;
    }

    private static string ReadCStringAt(byte[] buf, int offset, int maxLen)
    {
        if (offset < 0 || offset >= buf.Length) return "";
        int len = 0;
        while (len < maxLen && offset + len < buf.Length && buf[offset + len] != 0) len++;
        return System.Text.Encoding.ASCII.GetString(buf, offset, len);
    }
}

public class ResolutionCandidate
{
    public ulong Address;
    public RemoteModule Module;
}

public class IATSlot
{
    public List<ResolutionCandidate> Candidates;
    public int ChosenCandidate;
    public bool IsZero;
}