using System.Linq;
using System.Runtime.InteropServices;

namespace ThemidaUnpacker;

/// <summary>
/// In-target anti-anti-debug: patches PEB debug fields and installs lightweight
/// hooks on NtQueryInformationProcess / NtSetInformationThread so Themida's
/// debugger checks (DebugPort, DebugObjectHandle, ProcessDebugFlags,
/// ThreadHideFromDebugger) return a clean answer.
/// </summary>
public static class AntiDebug
{
    private static ulong VirtualAllocEx(IntPtr hProcess, int size)
    {
        ulong addr = 0x10000;
        ulong max = 0x00007FFFFFFF0000UL;
        while (addr < max)
        {
            IntPtr p = Native.VirtualAllocEx(hProcess, (IntPtr)addr, (nuint)size, Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_EXECUTE_READWRITE);
            if (p != IntPtr.Zero)
                return (ulong)p;
            addr += 0x10000;
        }
        return 0;
    }

    /// <summary>
    /// Installs a hook on apiAddress that fakes clean answers for the given
    /// "hidden" NT classes (edx), forwarding everything else to the original.
    /// The original 16 prologue bytes are copied into a trampoline.
    /// </summary>
    private static void InstallHiddenClassHook(IntPtr hProcess, ulong apiAddress, byte[] classes)
    {
        const int stubSize = 0x100;

        byte[] orig = new byte[16];
        if (!Native.ReadProcessMemory(hProcess, (IntPtr)apiAddress, orig, 16, out _))
            throw new Exception("AntiDebug: read prologue failed");

        byte[] stub = new byte[stubSize];
        int p = 0;

        void Emit(params byte[] bytes) { Array.Copy(bytes, 0, stub, p, bytes.Length); p += bytes.Length; }

        // Save caller registers (push order: rax, rcx, rdx, r8, r9, r10, r11).
        Emit(0x50);                       // push rax
        Emit(0x51);                       // push rcx
        Emit(0x52);                       // push rdx
        Emit(0x41, 0x50);                 // push r8
        Emit(0x41, 0x51);                 // push r9
        Emit(0x41, 0x52);                 // push r10
        Emit(0x41, 0x53);                 // push r11

        // Class checks: cmp edx, cls / je fake (rel8 patched after).
        int firstJe = p;
        foreach (byte cls in classes)
        {
            Emit(0x83, 0xFA, cls);        // cmp edx, cls
            Emit(0x74, 0x00);             // je fake
        }

        // Restore registers in reverse push order, jump to trampoline.
        Emit(0x41, 0x5B);                 // pop r11
        Emit(0x41, 0x5A);                 // pop r10
        Emit(0x41, 0x59);                 // pop r9
        Emit(0x41, 0x58);                 // pop r8
        Emit(0x5A);                       // pop rdx
        Emit(0x59);                       // pop rcx
        Emit(0x58);                       // pop rax
        int jmpTrampOff = p;
        Emit(0xE9, 0, 0, 0, 0);           // jmp trampoline (patched)

        // Trampoline: original prologue bytes, then continue at apiAddress+16.
        int trampOff = p;
        Array.Copy(orig, 0, stub, p, 16);
        p += 16;
        int jmpBackOff = p;
        Emit(0xE9, 0, 0, 0, 0);           // jmp original+16

        // Fake-success path at fixed offset 0x80: zero output buffer, return STATUS_SUCCESS.
        const int fakeOff = 0x80;
        p = fakeOff;
        Emit(0x41, 0x5B);
        Emit(0x41, 0x5A);
        Emit(0x41, 0x59);
        Emit(0x41, 0x58);
        Emit(0x5A);
        Emit(0x59);
        Emit(0x58);
        Emit(0x57);                       // push rdi (callee-saved)
        Emit(0x48, 0x89, 0xF7);           // mov rdi, r8  (buffer)
        Emit(0x48, 0x89, 0xCF);           // mov rcx, r9  (length)
        Emit(0x31, 0xC0);                 // xor eax, eax
        Emit(0xF3, 0xAA);                 // rep stosb  -> zero buffer
        Emit(0x5F);                       // pop rdi
        Emit(0x31, 0xC0);                 // xor eax, eax (STATUS_SUCCESS)
        Emit(0xC3);                       // ret

        // Patch je rel8 targets -> fakeOff.
        for (int i = 0; i < classes.Length; i++)
        {
            int jePos = firstJe + i * 5 + 3; // 0x83 0xFA cls 0x74 [rel8]
            stub[jePos + 1] = (byte)(fakeOff - (jePos + 2));
        }

        // jmp trampoline
        BitConverter.GetBytes(trampOff - (jmpTrampOff + 5)).CopyTo(stub, jmpTrampOff + 1);

        ulong alloc = VirtualAllocEx(hProcess, stubSize);
        if (alloc == 0)
            throw new Exception("AntiDebug: VirtualAllocEx failed");
        // jmp back to original+16 (runtime target: alloc + jmpBackOff + 5)
        BitConverter.GetBytes((int)(apiAddress + 16) - (int)(alloc + (ulong)jmpBackOff + 5)).CopyTo(stub, jmpBackOff + 1);
        if (!Native.WriteProcessMemory(hProcess, (IntPtr)alloc, stub, (nuint)stub.Length, out _))
            throw new Exception("AntiDebug: write stub failed");

        byte[] jmp = new byte[5];
        jmp[0] = 0xE9;
        BitConverter.GetBytes((int)(alloc - (apiAddress + 5))).CopyTo(jmp, 1);
        if (!Native.VirtualProtectEx(hProcess, (IntPtr)apiAddress, 5, Native.PAGE_EXECUTE_READWRITE, out _))
            throw new Exception("AntiDebug: protect prologue failed");
        if (!Native.WriteProcessMemory(hProcess, (IntPtr)apiAddress, jmp, 5, out _))
            throw new Exception("AntiDebug: patch prologue failed");

        Utils.Log(LogType.Good, $"Hooked 0x{apiAddress:X} (hidden classes {string.Join(",", classes.Select(c => "0x" + c.ToString("X2")))})");
    }

    /// <summary>Hooks NtQueryInformationProcess so DebugPort/object/flag checks stay clean.</summary>
    public static void HookNtQueryInformationProcess(IntPtr hProcess, ulong apiAddress)
    {
        InstallHiddenClassHook(hProcess, apiAddress, new byte[] { 0x07, 0x1E, 0x1F });
    }

    /// <summary>Hooks NtSetInformationThread so ThreadHideFromDebugger (class 0x11) is swallowed.</summary>
    public static void HookNtSetInformationThread(IntPtr hProcess, ulong apiAddress)
    {
        InstallHiddenClassHook(hProcess, apiAddress, new byte[] { 0x11 });
    }

    /// <summary>Clears PEB debug fields: NtGlobalFlag, BeingDebugged, pShimData.
    /// Heap flag patching is skipped: the modern segment-heap _HEAP layout on
    /// Win10+ has Flags/ForceFlags at different offsets and writing 0x18/0x40
    /// corrupts heap metadata (crashes loader init).</summary>
    public static void CleanPeb(IntPtr hProcess, ulong pebBase)
    {
        byte[] b = new byte[1] { 0 };
        Native.WriteProcessMemory(hProcess, (IntPtr)(pebBase + 2), b, 1, out _);

        if (Environment.GetEnvironmentVariable("TU_NGF") != "0")
        {
            byte[] g = new byte[4];
            Native.WriteProcessMemory(hProcess, (IntPtr)(pebBase + 0x68), g, 4, out _);
        }

        byte[] shim = new byte[8];
        Native.WriteProcessMemory(hProcess, (IntPtr)(pebBase + 0x2D8), shim, 8, out _);
    }
}