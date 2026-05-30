using HarmonyLib;
using System;
using System.IO;
using System.Reflection;

namespace Exorcism_PowershellEdition
{
    public class Loader
    {
        public static void Init()
        {
            var harmony = new Harmony("exorcism.pshook");
            harmony.PatchAll();
            Console.WriteLine("[+] Harmony patches applied: all Assembly load methods are now hooked.");
        }

        private static void DumpAssembly(byte[] rawAssembly, string suggestedName)
        {
            try
            {
                string safeName = string.IsNullOrWhiteSpace(suggestedName) ? "UnknownAssembly" : suggestedName;
                safeName = string.Join("_", safeName.Split(Path.GetInvalidFileNameChars()));

                string fileName = $"{safeName}_{Guid.NewGuid().ToString("N").Substring(0, 8)}.dll";
                string outPath = Path.Combine(Environment.CurrentDirectory, fileName);

                File.WriteAllBytes(outPath, rawAssembly);
                Console.WriteLine($"[+] Dumped assembly -> {outPath}");

                // Notify the Rust Backend Handler so antivirus.py knows about it!
                try
                {
                    using (var pipeClient = new System.IO.Pipes.NamedPipeClientStream(".", "HydraDragonDumper", System.IO.Pipes.PipeDirection.Out))
                    {
                        pipeClient.Connect(200); // Fast timeout
                        byte[] msg = System.Text.Encoding.UTF8.GetBytes("EXORCISM|" + outPath);
                        pipeClient.Write(msg, 0, msg.Length);
                        pipeClient.Flush();
                    }
                }
                catch { }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Dump error: {ex.Message}");
            }
        }

        // Assembly.Load(byte[])
        [HarmonyPatch(typeof(Assembly), nameof(Assembly.Load), new[] { typeof(byte[]) })]
        public static class AssemblyLoad_Bytes
        {
            public static void Postfix(byte[] rawAssembly, Assembly __result)
            {
                DumpAssembly(rawAssembly, __result.GetName().Name);
                Console.WriteLine($"[+] Loaded Assembly (byte[]): {__result.FullName}");
            }
        }

        // Assembly.Load(string)
        [HarmonyPatch(typeof(Assembly), nameof(Assembly.Load), new[] { typeof(string) })]
        public static class AssemblyLoad_String
        {
            public static void Postfix(string assemblyString, Assembly __result)
            {
                try
                {
                    if (__result != null && File.Exists(__result.Location))
                    {
                        byte[] raw = File.ReadAllBytes(__result.Location);
                        DumpAssembly(raw, __result.GetName().Name);
                    }
                }
                catch { }
                Console.WriteLine($"[+] Loaded Assembly (string): {__result?.FullName}");
            }
        }

        // Assembly.Load(AssemblyName)
        [HarmonyPatch(typeof(Assembly), nameof(Assembly.Load), new[] { typeof(AssemblyName) })]
        public static class AssemblyLoad_AsmName
        {
            public static void Postfix(AssemblyName assemblyRef, Assembly __result)
            {
                try
                {
                    if (__result != null && File.Exists(__result.Location))
                    {
                        byte[] raw = File.ReadAllBytes(__result.Location);
                        DumpAssembly(raw, __result.GetName().Name);
                    }
                }
                catch { }
                Console.WriteLine($"[+] Loaded Assembly (AssemblyName): {__result?.FullName}");
            }
        }

        // Assembly.LoadFrom(string)
        [HarmonyPatch(typeof(Assembly), nameof(Assembly.LoadFrom), new[] { typeof(string) })]
        public static class AssemblyLoadFrom
        {
            public static void Postfix(string assemblyFile, Assembly __result)
            {
                try
                {
                    if (File.Exists(assemblyFile))
                    {
                        byte[] raw = File.ReadAllBytes(assemblyFile);
                        DumpAssembly(raw, Path.GetFileNameWithoutExtension(assemblyFile));
                    }
                }
                catch { }
                Console.WriteLine($"[+] Loaded Assembly (LoadFrom): {__result?.FullName}");
            }
        }

        // Assembly.LoadFile(string)
        [HarmonyPatch(typeof(Assembly), nameof(Assembly.LoadFile), new[] { typeof(string) })]
        public static class AssemblyLoadFile
        {
            public static void Postfix(string path, Assembly __result)
            {
                try
                {
                    if (File.Exists(path))
                    {
                        byte[] raw = File.ReadAllBytes(path);
                        DumpAssembly(raw, Path.GetFileNameWithoutExtension(path));
                    }
                }
                catch { }
                Console.WriteLine($"[+] Loaded Assembly (LoadFile): {__result?.FullName}");
            }
        }
    }
}
