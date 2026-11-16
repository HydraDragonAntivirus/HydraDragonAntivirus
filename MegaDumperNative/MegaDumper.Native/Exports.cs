/*
 * Native exports of MegaDumper.dll (NativeAOT, no .NET runtime needed), for
 * OpenEDR's edrsvc to load with LoadLibrary / GetProcAddress.
 *
 *   int  megadumper_enable_debug_privilege(void);
 *   int  megadumper_dump_process(uint32_t pid, const wchar_t* outputDir,
 *                                int dumpNative, int restoreFilename,
 *                                wchar_t* result, uint32_t resultCap);
 *
 * megadumper_dump_process returns 0 when the dump ran, 1 on bad arguments,
 * 2 when the output directory could not be created, 3 on a failure inside the
 * dump. `result` (optional) receives the dump's summary or the error text,
 * NUL-terminated and cut to resultCap characters. Each call uses its own
 * Dumper, so calls from several threads do not share state. No exception
 * leaves the DLL.
 */
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Mega_Dumper
{
    public static unsafe class Exports
    {
        [UnmanagedCallersOnly(EntryPoint = "megadumper_enable_debug_privilege", CallConvs = new[] { typeof(CallConvCdecl) })]
        public static int EnableDebugPrivilege()
        {
            try
            {
                new Dumper().EnableDebuggerPrivileges();
                return 0;
            }
            catch
            {
                return 1;
            }
        }

        [UnmanagedCallersOnly(EntryPoint = "megadumper_dump_process", CallConvs = new[] { typeof(CallConvCdecl) })]
        public static int DumpProcess(uint processId, char* outputDir, int dumpNative, int restoreFilename,
            char* result, uint resultCap)
        {
            string text;
            int code;
            try
            {
                string dir = outputDir == null ? null : new string(outputDir);
                if (processId == 0 || string.IsNullOrWhiteSpace(dir))
                {
                    text = "Error: a process id and an output directory are required.";
                    code = 1;
                }
                else
                {
                    var dumper = new Dumper();
                    var dirs = new Dumper.DUMP_DIRECTORIES { root = Path.GetFullPath(dir) };
                    if (!dumper.CreateDirectoriesCli(ref dirs))
                    {
                        text = "Error: could not create the output directory " + dirs.root;
                        code = 2;
                    }
                    else
                    {
                        text = dumper.DumpProcess(processId, dirs, dumpNative != 0, restoreFilename != 0);
                        code = 0;
                    }
                }
            }
            catch (Exception ex)
            {
                text = "Error: " + ex.GetType().Name + ": " + ex.Message;
                code = 3;
            }
            CopyOut(text, result, resultCap);
            return code;
        }

        private static void CopyOut(string text, char* buffer, uint capacity)
        {
            if (buffer == null || capacity == 0)
                return;
            text ??= string.Empty;
            int n = (int)Math.Min((uint)text.Length, capacity - 1);
            for (int i = 0; i < n; i++)
                buffer[i] = text[i];
            buffer[n] = '\0';
        }
    }
}
