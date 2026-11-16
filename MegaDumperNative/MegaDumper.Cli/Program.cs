/*
 * Mega Dumper - console entry point. The GUI is gone; the dump engine is
 * Dumper.cs, shared with MegaDumper.dll.
 */

using System;
using System.IO;

namespace Mega_Dumper
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            if (args == null || args.Length == 0)
            {
                PrintUsage();
                return 2;
            }
            return RunCli(args);
        }

        /// <summary>
        /// Main CLI logic. Returns exit codes: 0=ok, 1=error, 2=bad usage
        /// </summary>
        private static int RunCli(string[] args)
        {
            try
            {
                // Parsed options
                uint pid = 0;
                string outputPath = null;
                bool waitForKey = false; // --wait to pause at the end so user can read messages
                bool restoreFilename = true;

                // Simple parsing loop
                for (int i = 0; i < args.Length; i++)
                {
                    var token = args[i];
                    switch (token.ToLowerInvariant())
                    {
                        case "--help":
                        case "-h":
                        case "/?":
                            PrintUsage();
                            return 0;

                        case "--pid":
                            if (i + 1 < args.Length && uint.TryParse(args[++i], out pid))
                            {
                                // parsed
                            }
                            else
                            {
                                Console.Error.WriteLine("Error: --pid requires a valid integer process ID.");
                                PrintUsage();
                                return 2;
                            }
                            break;

                        case "--output":
                            if (i + 1 < args.Length)
                            {
                                outputPath = args[++i];
                            }
                            else
                            {
                                Console.Error.WriteLine("Error: --output requires a target directory path.");
                                PrintUsage();
                                return 2;
                            }
                            break;

                        case "--wait":
                            waitForKey = true;
                            break;

                        case "--no-restore-filename":
                            restoreFilename = false;
                            break;

                        default:
                            Console.Error.WriteLine($"Error: Unknown argument '{token}'");
                            PrintUsage();
                            return 2;
                    }
                }

                var logic = new Dumper();
                logic.EnableDebuggerPrivileges();

                // Dumping a process: require both pid and output path
                if (pid > 0 && !string.IsNullOrWhiteSpace(outputPath))
                {
                    try
                    {
                        string fullOut = Path.GetFullPath(outputPath);
                        Console.WriteLine($"Attempting to dump process PID={pid} into directory: '{fullOut}'...");

                        // Create directory if it doesn't exist
                        try
                        {
                            Directory.CreateDirectory(fullOut);
                        }
                        catch (Exception dirEx)
                        {
                            Console.Error.WriteLine($"Failed to create output directory: {dirEx.Message}");
                            if (waitForKey) { Console.WriteLine("Press any key to exit..."); Console.ReadKey(true); }
                            return 1;
                        }

                        string result = logic.DumpProcessByIdCli(pid, fullOut, restoreFilename);
                        Console.WriteLine($"Result: {result}");
                        if (waitForKey) { Console.WriteLine("Press any key to exit..."); Console.ReadKey(true); }
                        return 0;
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"Dump failed: {ex}");
                        if (waitForKey) { Console.WriteLine("Press any key to exit..."); Console.ReadKey(true); }
                        return 1;
                    }
                }

                // If we reach here the argument combination was invalid
                Console.Error.WriteLine("Error: Missing required arguments. Provide --pid and --output.");
                PrintUsage();
                if (waitForKey) { Console.WriteLine("Press any key to exit..."); Console.ReadKey(true); }
                return 2;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Unhandled exception: {ex}");
                Console.Error.WriteLine("Exiting with error.");
                return 1;
            }
        }

        private static void PrintUsage()
        {
            Console.WriteLine();
            Console.WriteLine("===========================");
            Console.WriteLine("  Mega Dumper CLI Usage");
            Console.WriteLine("===========================");
            Console.WriteLine();
            Console.WriteLine("To dump a process by its PID:");
            Console.WriteLine("  MegaDumper.exe --pid <ProcessID> --output <TargetDirectoryPath> [--no-restore-filename] [--wait]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  --no-restore-filename    Keep rawdump_*/vdump_* filenames and skip sorted filename restoration");
            Console.WriteLine("  --wait    Pause and wait for a keypress before the program exits (helpful when double-clicking the exe)");
            Console.WriteLine("  --help    Show this help message");
            Console.WriteLine();
        }
    }
}
