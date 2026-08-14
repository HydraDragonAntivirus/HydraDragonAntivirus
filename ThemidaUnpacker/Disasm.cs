namespace ThemidaUnpacker;

/// <summary>Classification of a decoded x64 instruction relevant to IAT scanning.</summary>
public enum X64InsnKind
{
    Other,
    CallPtr,   // call qword ptr [rip+disp32]
    JmpPtr,    // jmp qword ptr [rip+disp32]
    CallRel,   // call rel32
    Ret,       // ret / ret imm16
    MovRaxPtr, // mov reg, [rip+disp32]
}

public struct X64Insn
{
    public int Length;
    public X64InsnKind Kind;
    public ulong RipDisp;   // absolute target address of the rip-relative memory operand
    public ulong RelTarget; // absolute target of call rel32
}

/// <summary>
/// Minimal x64 instruction length/classification decoder used to locate IAT references
/// near the OEP (port of the BeaEngine usage in Magicmida's ThemidaCommon.pas).
/// </summary>
public static class Disasm
{
    private const int ModRM_FLAG = 0x80;

    // Primary opcode table: high bit = ModRM follows, low bits = immediate size (0,1,2,4,8).
    private static readonly byte[] Op0 = BuildOp0();
    // Two-byte (0F) opcode table.
    private static readonly byte[] Op0F = BuildOp0F();

    public static X64Insn Decode(byte[] code, int offset, int size, ulong virtualAddr)
    {
        var insn = new X64Insn { Kind = X64InsnKind.Other, Length = 1 };
        int ip = offset;
        int end = Math.Min(offset + 15, size); // max x64 instruction length

        bool has66 = false, has67 = false, rexW = false;
        while (ip < end)
        {
            byte b = code[ip];
            if (b == 0x66) { has66 = true; ip++; continue; }
            if (b == 0x67) { has67 = true; ip++; continue; }
            if (b == 0xF0 || b == 0xF2 || b == 0xF3) { ip++; continue; }
            if ((b & 0xF0) == 0x40 && (b & 0x0F) != 0) // REX (non-empty)
            {
                if ((b & 0x08) != 0) rexW = true;
                ip++; continue;
            }
            break;
        }
        if (ip >= end) { insn.Length = ip - offset; return insn; }

        byte op = code[ip];
        int opStart = ip;
        int prefixLen = opStart - offset;

        if (op == 0x0F)
        {
            if (ip + 1 >= end) { insn.Length = opStart - offset + 1; return insn; }
            byte op2 = code[ip + 1];
            byte info0F = Op0F[op2];
            bool modrm = (info0F & ModRM_FLAG) != 0;
            int imm = info0F & 0x0F;
            int len = 2;
            ulong ripTarget = 0;

            if (modrm)
            {
                int mrm = ip + 2;
                len = DecodeModRM(code, mrm, end, modrm, out ripTarget);
            }
            len += imm;
            if (has66 && (imm == 2 || imm == 4)) len -= 2;
            if (has66 && imm == 8) len -= 4;
            insn.Length = prefixLen + len;
            return insn;
        }

        byte info = Op0[op];
        bool hasModRM = (info & ModRM_FLAG) != 0;
        int immSize = info & 0x0F;
        int total = opStart - offset + 1;
        ulong ripTarget2 = 0;

        // Opcode-specific handling
        switch (op)
        {
            case 0xFF:
                // group 5: /2 call, /4 jmp. Detect FF 15 / FF 25 => call/jmp qword ptr [rip+disp32]
                if (ip + 1 >= end) { insn.Length = total; return insn; }
                {
                    byte mrm = code[ip + 1];
                    int mod = mrm >> 6;
                    int reg = (mrm >> 3) & 7;
                    int rm = mrm & 7;
                    if (mod == 0 && rm == 5 && (reg == 2 || reg == 4) && ip + 5 < end)
                    {
                        int disp = BitConverter.ToInt32(code, ip + 2);
                        int totalLen = prefixLen + 6;
                        insn.Kind = reg == 2 ? X64InsnKind.CallPtr : X64InsnKind.JmpPtr;
                        insn.RipDisp = virtualAddr + (ulong)totalLen + (ulong)disp;
                        insn.Length = totalLen;
                        return insn;
                    }
                    int len2 = DecodeModRM(code, ip + 1, end, true, out ripTarget2);
                    insn.Length = total + len2;
                    return insn;
                }
            case 0xE8:
                if (ip + 4 < end)
                {
                    int rel = BitConverter.ToInt32(code, ip + 1);
                    insn.Kind = X64InsnKind.CallRel;
                    insn.RelTarget = virtualAddr + (ulong)(prefixLen + 5) + (ulong)rel;
                    insn.Length = prefixLen + 5;
                    return insn;
                }
                insn.Length = total;
                return insn;
            case 0xE9:
                if (ip + 4 < end) { insn.Length = prefixLen + 5; return insn; }
                insn.Length = total;
                return insn;
            case 0xC3:
                insn.Kind = X64InsnKind.Ret;
                insn.Length = prefixLen + 1;
                return insn;
            case 0xC2:
                insn.Kind = X64InsnKind.Ret;
                insn.Length = prefixLen + 3;
                return insn;
            case 0x8B:
                // mov r32/r64, r/m - could be "mov rax, [rip+disp]" (Go API call pattern)
                if (ip + 1 < end)
                {
                    byte mrm = code[ip + 1];
                    int mod = mrm >> 6;
                    int rm = mrm & 7;
                    if (mod == 0 && rm == 5 && ip + 5 < end)
                    {
                        int disp = BitConverter.ToInt32(code, ip + 2);
                        int totalLen = prefixLen + 6;
                        insn.Kind = X64InsnKind.MovRaxPtr;
                        insn.RipDisp = virtualAddr + (ulong)totalLen + (ulong)disp;
                        insn.Length = totalLen;
                        return insn;
                    }
                    int len3 = DecodeModRM(code, ip + 1, end, true, out ripTarget2);
                    insn.Length = total + len3;
                    return insn;
                }
                insn.Length = total;
                return insn;
        }

        if (hasModRM)
        {
            int len4 = DecodeModRM(code, ip + 1, end, true, out ripTarget2);
            total += len4;
        }

        if (immSize > 0)
        {
            if (has66 && (immSize == 2 || immSize == 4)) immSize -= 2;
            if (rexW && immSize == 8) immSize = 8;
            total += immSize;
        }

        // Immediate-only opcodes not covered by table imm sizes (B0-B7/B8-BF etc are in table).
        insn.Length = total;
        return insn;
    }

    private static int DecodeModRM(byte[] code, int mrmOff, int end, bool hasModRM, out ulong ripTarget)
    {
        ripTarget = 0;
        if (!hasModRM || mrmOff >= end) return 0;
        byte mrm = code[mrmOff];
        int mod = mrm >> 6;
        int rm = mrm & 7;
        int len = 1;

        if (mod == 0 && rm == 5)
        {
            // RIP-relative disp32 (no SIB)
            len += 4;
            return len;
        }
        if (mod == 1)
        {
            len += 1;
        }
        else if (mod == 2)
        {
            len += 4;
        }

        if (rm == 4)
        {
            // SIB byte
            len += 1;
            if (mrmOff + len >= end) return len;
            int sibBase = code[mrmOff + len - 1] & 7;
            if (mod == 0 && sibBase == 5)
                len += 4;
        }
        return len;
    }

    private static byte[] BuildOp0()
    {
        var t = new byte[256];

        // Group 1 ALU r/m,reg (ModRM)
        t[0x00] = ModRM_FLAG; t[0x01] = ModRM_FLAG; t[0x02] = ModRM_FLAG; t[0x03] = ModRM_FLAG;
        t[0x08] = ModRM_FLAG; t[0x09] = ModRM_FLAG; t[0x0A] = ModRM_FLAG; t[0x0B] = ModRM_FLAG;
        t[0x10] = ModRM_FLAG; t[0x11] = ModRM_FLAG; t[0x12] = ModRM_FLAG; t[0x13] = ModRM_FLAG;
        t[0x18] = ModRM_FLAG; t[0x19] = ModRM_FLAG; t[0x1A] = ModRM_FLAG; t[0x1B] = ModRM_FLAG;
        t[0x20] = ModRM_FLAG; t[0x21] = ModRM_FLAG; t[0x22] = ModRM_FLAG; t[0x23] = ModRM_FLAG;
        t[0x28] = ModRM_FLAG; t[0x29] = ModRM_FLAG; t[0x2A] = ModRM_FLAG; t[0x2B] = ModRM_FLAG;
        t[0x30] = ModRM_FLAG; t[0x31] = ModRM_FLAG; t[0x32] = ModRM_FLAG; t[0x33] = ModRM_FLAG;
        t[0x38] = ModRM_FLAG; t[0x39] = ModRM_FLAG; t[0x3A] = ModRM_FLAG; t[0x3B] = ModRM_FLAG;
        t[0x04] = 1; t[0x0C] = 1; t[0x14] = 1; t[0x1C] = 1; t[0x24] = 1; t[0x2C] = 1; t[0x34] = 1; t[0x3C] = 1;
        t[0x05] = 4; t[0x0D] = 4; t[0x15] = 4; t[0x1D] = 4; t[0x25] = 4; t[0x2D] = 4; t[0x35] = 4; t[0x3D] = 4;

        // MOV group
        for (int op = 0x88; op <= 0x8F; op++)
            t[op] = ModRM_FLAG;
        t[0x8D] = ModRM_FLAG; // lea

        // TEST/XCHG
        t[0x84] = ModRM_FLAG; t[0x85] = ModRM_FLAG; t[0x86] = ModRM_FLAG; t[0x87] = ModRM_FLAG;

        // Group 1 imm variants
        t[0x80] = ModRM_FLAG | 1; // r/m8,imm8
        t[0x81] = ModRM_FLAG | 4; // r/m,imm32
        t[0x83] = ModRM_FLAG | 1; // r/m,imm8
        t[0xC0] = ModRM_FLAG | 1; // rol/ror/etc r/m8,imm8
        t[0xC1] = ModRM_FLAG | 1; // rol/ror/etc r/m,imm8
        t[0xC6] = ModRM_FLAG | 1; // mov r/m8,imm8
        t[0xC7] = ModRM_FLAG | 4; // mov r/m,imm32
        t[0xF6] = ModRM_FLAG;     // group3 (NOT/NEG/etc) - imm handled below
        t[0xF7] = ModRM_FLAG;

        // Shift group (D0-D3) - ModRM
        t[0xD0] = ModRM_FLAG; t[0xD1] = ModRM_FLAG; t[0xD2] = ModRM_FLAG; t[0xD3] = ModRM_FLAG;

        // Group 4/5 (FE/FF) handled specially
        t[0xFE] = ModRM_FLAG;
        t[0xFF] = ModRM_FLAG;

        // x87 (D8-DF) - ModRM
        for (int op = 0xD8; op <= 0xDF; op++)
            t[op] = ModRM_FLAG;

        // MOV r8/imm8 (B0-B7) and MOV r,imm (B8-BF)
        for (int op = 0xB0; op <= 0xB7; op++)
            t[op] = 1;
        for (int op = 0xB8; op <= 0xBF; op++)
            t[op] = 8; // imm64 (REX.W) or imm32; rexW handling above

        // Jcc rel8 (70-7F), LOOP/JMP rel8 (E0-EB)
        for (int op = 0x70; op <= 0x7F; op++)
            t[op] = 1;
        t[0xE0] = 1; t[0xE1] = 1; t[0xE2] = 1; t[0xE3] = 1;
        t[0xEB] = 1;

        // MOV moffs (A0-A3): 8-byte address in 64-bit mode
        t[0xA0] = 8; t[0xA1] = 8; t[0xA2] = 8; t[0xA3] = 8;
        t[0xA8] = 1; t[0xA9] = 4; // TEST AL/imm8, TEST eAX/imm32

        // Enter/Ret
        t[0xC2] = 2; // ret imm16
        t[0xC8] = 4; // enter imm16, imm8
        t[0xCA] = 2; // retf imm16

        return t;
    }

    private static byte[] BuildOp0F()
    {
        var t = new byte[256];
        // Default: length 2, no modrm
        for (int i = 0; i < 256; i++)
            t[i] = 0;

        // ModRM-present groups in 0F table
        // 0F 00-01: group 6/7 (modrm)
        t[0x00] = ModRM_FLAG; t[0x01] = ModRM_FLAG;
        // LAR/LSL/... (02,03) modrm
        t[0x02] = ModRM_FLAG; t[0x03] = ModRM_FLAG;
        // MOV CR/DR (20-23) modrm
        t[0x20] = ModRM_FLAG; t[0x21] = ModRM_FLAG; t[0x22] = ModRM_FLAG; t[0x23] = ModRM_FLAG;
        // CMOVcc (40-4F)
        for (int op = 0x40; op <= 0x4F; op++)
            t[op] = ModRM_FLAG;
        // SSE/SIMD modrm (10-1F, 28-2F, 50-7F, 90-9F...)
        for (int op = 0x10; op <= 0x1F; op++) t[op] = ModRM_FLAG;
        for (int op = 0x28; op <= 0x2F; op++) t[op] = ModRM_FLAG;
        for (int op = 0x50; op <= 0x6F; op++) t[op] = ModRM_FLAG;
        for (int op = 0x90; op <= 0x9F; op++) t[op] = ModRM_FLAG;
        // SETcc etc are 90-9F (already done)
        // IMUL/MOVSX etc (AF-BF)
        t[0xA3] = ModRM_FLAG; t[0xA4] = ModRM_FLAG | 1; t[0xA5] = ModRM_FLAG;
        t[0xAB] = ModRM_FLAG; t[0xAC] = ModRM_FLAG | 1; t[0xAD] = ModRM_FLAG;
        t[0xAF] = ModRM_FLAG;
        t[0xB0] = ModRM_FLAG; t[0xB1] = ModRM_FLAG; t[0xB2] = ModRM_FLAG; t[0xB3] = ModRM_FLAG;
        t[0xB4] = ModRM_FLAG; t[0xB5] = ModRM_FLAG;
        t[0xB6] = ModRM_FLAG; t[0xB7] = ModRM_FLAG;
        t[0xB8] = ModRM_FLAG; t[0xB9] = ModRM_FLAG; t[0xBA] = ModRM_FLAG | 1; t[0xBB] = ModRM_FLAG;
        t[0xBC] = ModRM_FLAG; t[0xBD] = ModRM_FLAG; t[0xBE] = ModRM_FLAG; t[0xBF] = ModRM_FLAG;
        // CMPXCHG8B (C7) modrm
        t[0xC7] = ModRM_FLAG;
        // XADD (C0-C1)
        t[0xC0] = ModRM_FLAG; t[0xC1] = ModRM_FLAG;
        // SSE with imm8 (C2-C6, 70-7F)
        for (int op = 0x70; op <= 0x7F; op++)
            t[op] = ModRM_FLAG | 1;
        t[0xC2] = ModRM_FLAG | 1;
        t[0xC4] = ModRM_FLAG | 1; t[0xC5] = ModRM_FLAG | 1; t[0xC6] = ModRM_FLAG | 1;
        // PSHUFW etc

        // MOVNTI etc (C3) modrm
        t[0xC3] = ModRM_FLAG;

        // BSWAP (C8-CF) length 2
        // (default)

        // SSE2/AVX-ish modrm for D0-FF
        for (int op = 0xD0; op <= 0xEF; op++) t[op] = ModRM_FLAG;
        t[0xF0] = ModRM_FLAG;
        for (int op = 0xF1; op <= 0xF8; op++) t[op] = ModRM_FLAG;
        t[0xFA] = ModRM_FLAG; t[0xFB] = ModRM_FLAG; t[0xFC] = ModRM_FLAG; t[0xFD] = ModRM_FLAG; t[0xFE] = ModRM_FLAG; t[0xFF] = ModRM_FLAG;

        // Jcc rel32 (80-8F) length 6
        for (int op = 0x80; op <= 0x8F; op++)
            t[op] = 4;

        return t;
    }
}
