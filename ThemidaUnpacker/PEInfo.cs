using System.Runtime.InteropServices;

namespace ThemidaUnpacker;

public class PESection
{
    public IMAGE_SECTION_HEADER Header;
    public byte[] Data;

    public void Rename(string newName)
    {
        var nameBytes = new byte[8];
        int n = Math.Min(newName.Length, 8);
        for (int i = 0; i < n; i++) nameBytes[i] = (byte)newName[i];
        Header.Name = nameBytes;
    }
}

public class PEHeader
{
    public IMAGE_NT_HEADERS64 NTHeaders;
    public List<PESection> Sections;
    public uint LFANew;
    public uint DumpSize;

    public PEHeader(byte[] data)
    {
        LFANew = BitConverter.ToUInt32(data, 0x3C);
        var nt = new byte[24 + 224]; // signature + fileheader + optionalheader64
        Array.Copy(data, (int)LFANew, nt, 0, nt.Length);
        NTHeaders = MarshalBytesToStruct<IMAGE_NT_HEADERS64>(nt);
        DumpSize = NTHeaders.OptionalHeader.SizeOfImage;

        int numSec = NTHeaders.FileHeader.NumberOfSections;
        Sections = new List<PESection>();
        int secOff = (int)LFANew + 24 + NTHeaders.FileHeader.SizeOfOptionalHeader;
        for (int i = 0; i < numSec; i++)
        {
            var shBytes = new byte[Marshal.SizeOf<IMAGE_SECTION_HEADER>()];
            if (secOff + shBytes.Length > data.Length) break;
            Array.Copy(data, secOff, shBytes, 0, shBytes.Length);
            var sh = MarshalBytesToStruct<IMAGE_SECTION_HEADER>(shBytes);
            Sections.Add(new PESection { Header = sh });
            secOff += shBytes.Length;
        }
    }

    public static T MarshalBytesToStruct<T>(byte[] data) where T : struct
    {
        var handle = GCHandle.Alloc(data, GCHandleType.Pinned);
        try
        {
            return Marshal.PtrToStructure<T>(handle.AddrOfPinnedObject());
        }
        finally
        {
            handle.Free();
        }
    }

    public PESection CreateSection(string name, uint size)
    {
        var prev = Sections[Sections.Count - 1];
        var sec = new PESection();
        sec.Header.Name = new byte[8];
        int n = Math.Min(name.Length, 8);
        for (int i = 0; i < n; i++) sec.Header.Name[i] = (byte)name[i];

        sec.Header.VirtualSize = size;
        sec.Header.VirtualAddress = prev.Header.VirtualAddress + prev.Header.VirtualSize;
        SectionAlign(ref sec.Header.VirtualAddress);
        sec.Header.PointerToRawData = NTHeaders.OptionalHeader.SizeOfImage;
        sec.Header.SizeOfRawData = size;
        sec.Header.Characteristics = Native.IMAGE_SCN_MEM_READ | Native.IMAGE_SCN_CNT_INITIALIZED_DATA;
        Sections.Add(sec);
        NTHeaders.OptionalHeader.SizeOfImage += size;
        return sec;
    }

    public void DeleteSection(int idx)
    {
        var sec = Sections[idx];
        bool isLast = idx == Sections.Count - 1;

        uint sz;
        if (isLast)
            sz = NTHeaders.OptionalHeader.SizeOfImage - sec.Header.SizeOfRawData;
        else
            sz = Sections[idx + 1].Header.PointerToRawData - sec.Header.PointerToRawData;

        for (int i = Sections.Count - 1; i >= idx + 1; i--)
            Sections[i].Header.PointerToRawData -= sz;

        var prev = Sections[idx - 1];
        prev.Header.VirtualSize += sec.Header.VirtualSize;
        SectionAlign(ref prev.Header.VirtualSize);

        Sections.RemoveAt(idx);
        NTHeaders.FileHeader.NumberOfSections = (ushort)Sections.Count;
    }

    public PESection GetSectionByVA(uint v)
    {
        foreach (var s in Sections)
            if (s.Header.VirtualAddress + s.Header.VirtualSize > v)
                return s;
        return null;
    }

    public void Sanitize()
    {
        foreach (var s in Sections)
        {
            s.Header.PointerToRawData = s.Header.VirtualAddress;
            s.Header.SizeOfRawData = s.Header.VirtualSize;
        }
        NTHeaders.OptionalHeader.SizeOfHeaders = Sections[0].Header.PointerToRawData;
        Sections[0].Header.Characteristics |= Native.IMAGE_SCN_MEM_WRITE;
    }

    public byte[] ToBytes()
    {
        int hdrSize = 24 + NTHeaders.FileHeader.SizeOfOptionalHeader + Sections.Count * 40;
        var buf = new byte[hdrSize + 0x200];
        var ntBytes = StructToBytes(NTHeaders);
        Array.Copy(ntBytes, 0, buf, (int)LFANew, ntBytes.Length);

        int off = (int)LFANew + 24 + NTHeaders.FileHeader.SizeOfOptionalHeader;
        foreach (var s in Sections)
        {
            var shBytes = StructToBytes(s.Header);
            Array.Copy(shBytes, 0, buf, off, shBytes.Length);
            off += 40;
        }
        return buf;
    }

    public static byte[] StructToBytes<T>(T value) where T : struct
    {
        int size = Marshal.SizeOf<T>();
        var buf = new byte[size];
        var handle = GCHandle.Alloc(buf, GCHandleType.Pinned);
        try
        {
            Marshal.StructureToPtr(value, handle.AddrOfPinnedObject(), false);
        }
        finally
        {
            handle.Free();
        }
        return buf;
    }

    /// <summary>Trims trailing zeros of sections that are >= 1MB bloated. Returns total delta trimmed.</summary>
    public uint TrimHugeSections(byte[] buf, ref uint iatRawAddr)
    {
        uint result = 0;
        for (int i = 0; i < NTHeaders.FileHeader.NumberOfSections; i++)
        {
            uint sectionStart = Sections[i].Header.PointerToRawData;
            long zeroStart = -1;

            uint rsd = Sections[i].Header.SizeOfRawData;
            for (long j = (rsd / 4) - 1; j >= 0; j--)
            {
                ulong off = (ulong)sectionStart + (ulong)(j * 4);
                if (off + 4 > (ulong)buf.Length) break;
                if (BitConverter.ToUInt32(buf, (int)off) == 0)
                    zeroStart = j * 4;
                else
                    break;
            }

            if (zeroStart != -1 && (Sections[i].Header.SizeOfRawData - (uint)zeroStart > 1024 * 1024))
            {
                uint oldSize = Sections[i].Header.SizeOfRawData;
                SectionAlign(ref oldSize);

                uint newSize = (uint)zeroStart;
                FileAlign(ref newSize);
                Utils.Log(LogType.Info, $"Reducing size of section [{Utils.AnsiString(Sections[i].Header.Name)}]: {oldSize:X} -> {newSize:X}");
                uint delta = oldSize - newSize;
                result += delta;
                Sections[i].Header.SizeOfRawData = newSize;

                if (i < Sections.Count - 1)
                {
                    // move data
                    uint nextStart = Sections[i + 1].Header.PointerToRawData;
                    int copyLen = (int)(DumpSize - sectionStart - oldSize);
                    if ((long)sectionStart + newSize + copyLen <= buf.Length && nextStart + copyLen <= buf.Length)
                    {
                        Array.Copy(buf, (int)nextStart, buf, (int)(sectionStart + newSize), copyLen);
                    }
                    for (int j = i + 1; j < Sections.Count; j++)
                        Sections[j].Header.PointerToRawData -= delta;
                }

                if (iatRawAddr >= sectionStart + oldSize)
                    iatRawAddr -= delta;
            }
        }
        return result;
    }

    public void FileAlign(ref uint v)
    {
        uint delta = v % NTHeaders.OptionalHeader.FileAlignment;
        if (delta > 0) v += NTHeaders.OptionalHeader.FileAlignment - delta;
    }

    public void SectionAlign(ref uint v)
    {
        uint delta = v % NTHeaders.OptionalHeader.SectionAlignment;
        if (delta > 0) v += NTHeaders.OptionalHeader.SectionAlignment - delta;
    }

    public ulong ConvertOffsetToRVAVector(ulong offset)
    {
        foreach (var s in Sections)
            if (s.Header.PointerToRawData <= offset && s.Header.PointerToRawData + s.Header.SizeOfRawData > offset)
                return (offset - s.Header.PointerToRawData) + s.Header.VirtualAddress;
        return 0;
    }

    public void RenameSection(int idx, string name)
    {
        Sections[idx].Rename(name);
    }
}