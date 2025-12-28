/*
 * Rewritten Program.cs
 * Hybrid GUI + CLI entry point for Mega_Dumper
 * - Supports GUI when run without arguments
 * - Supports CLI when run with arguments
 * - Allocates a console automatically when needed (so this file can be used in a Windows Application build)
 * - Better argument parsing, exit codes, and optional pause-for-read (--wait)
 * - CRITICAL: Enables legacy corrupted state exception handling for .NET 8 compatibility with Scylla.dll
 */

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Mega_Dumper
{
    internal static class Program
    {
        // If the project is compiled as a "Windows Application", there is no console by default.
        // These kernel32 calls let us allocate a console at runtime so Console.WriteLine works.
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AllocConsole();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeConsole();

        /// <summary>
        /// Static constructor runs BEFORE Main(). This is critical for setting up
        ///環境 variables that must be present before P/Invoke calls are made.
        /// </summary>
        static Program()
        {
            // CRITICAL: Enable legacy corrupted state exception handling for .NET 8
            // Without this, AccessViolationException from Scylla.dll P/Invoke calls
            // will terminate the process. This MUST be set before any P/Invoke calls.
            try
            {
                Environment.SetEnvironmentVariable("COMPlus_legacyCorruptedStateExceptionsPolicy", "1");
            }
            catch
            {
                // If this fails, we're in trouble but don't crash here
            }
        }

        /// <summary>
        /// Single entry point. Runs GUI when no arguments are present, otherwise runs CLI mode.
        /// Keep this method synchronous and STA so WinForms/WPF behavior remains correct.
        /// </summary>
        [STAThread]
        private static int Main(string[] args)
        {
            // Set up global exception handlers to prevent crashes
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
            TaskScheduler.UnobservedTaskException += TaskScheduler_UnobservedTaskException;
            Application.ThreadException += Application_ThreadException;
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);

            // No args -> normal GUI mode
            if (args == null || args.Length == 0)
            {
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new MainForm());
                return 0;
            }


            // We have CLI args: ensure a console is present (useful when built as Windows Application)
            if (!AllocConsole())
            {
                // If AllocConsole fails, we still attempt to run; Console calls will no-op.
                // We don't exit here because sometimes AllocConsole fails when launched from an existing console.
            }

            try
            {
                int exitCode = RunCli(args).GetAwaiter().GetResult();
                // Optionally free the console — commented out because freeing may close the window immediately.
                // FreeConsole();
                return exitCode;
            }
            finally
            {
                // Leave the console open/attached so users running from Explorer can read output.
                // If you want the console to go away immediately, uncomment FreeConsole() above.
            }
        }

        /// <summary>
        /// Main CLI logic. Returns exit codes: 0=ok, 1=error, 2=bad usage
        /// </summary>
        private static async Task<int> RunCli(string[] args)
        {
            try
            {
                // Parsed options
                uint pid = 0;
                string outputPath = null;
                bool waitForKey = false; // --wait to pause at the end so user can read messages

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

                        default:
                            Console.Error.WriteLine($"Error: Unknown argument '{token}'");
                            PrintUsage();
                            return 2;
                    }
                }

                // Reuse existing logic on MainForm (keeps changes minimal). If you prefer, extract logic into a separate class.
                var logic = new MainForm();
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

                        string result = await logic.DumpProcessByIdCli(pid, fullOut).ConfigureAwait(false);
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
            Console.WriteLine("  Mega_Dumper.exe --pid <ProcessID> --output <TargetDirectoryPath> [--wait]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  --wait    Pause and wait for a keypress before the program exits (helpful when double-clicking the exe)");
            Console.WriteLine("  --help    Show this help message");
            Console.WriteLine();
        }

        /// <summary>
        /// Handles unhandled exceptions on the AppDomain level
        /// </summary>
        private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            try
            {
                var ex = e.ExceptionObject as Exception;
                string message = ex != null 
                    ? $"Unhandled exception: {ex.GetType().Name} - {ex.Message}\n{ex.StackTrace}"
                    : "Unknown unhandled exception";
                
                // Log to file
                try
                {
                    string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "crash_log.txt");
                    File.AppendAllText(logPath, $"[{DateTime.Now}] {message}\n\n");
                }
                catch { /* Can't log, nothing we can do */ }

                // Show message if possible (non-terminating exceptions)
                if (!e.IsTerminating)
                {
                    MessageBox.Show($"An error occurred:\n\n{ex?.Message ?? "Unknown error"}\n\nThe operation will continue if possible.", 
                        "MegaDumper Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
            catch { /* Catastrophic failure - can't handle it */ }
        }

        /// <summary>
        /// Handles unobserved task exceptions (async exceptions that weren't awaited)
        /// </summary>
        private static void TaskScheduler_UnobservedTaskException(object sender, UnobservedTaskExceptionEventArgs e)
        {
            try
            {
                // Mark as observed to prevent crash
                e.SetObserved();
                
                string message = $"Unobserved task exception: {e.Exception?.Message}\n{e.Exception?.StackTrace}";
                
                // Log to file
                try
                {
                    string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "crash_log.txt");
                    File.AppendAllText(logPath, $"[{DateTime.Now}] {message}\n\n");
                }
                catch { }
            }
            catch { }
        }

        /// <summary>
        /// Handles exceptions on the Windows Forms UI thread
        /// </summary>
        private static void Application_ThreadException(object sender, System.Threading.ThreadExceptionEventArgs e)
        {
            try
            {
                string message = $"UI thread exception: {e.Exception?.GetType().Name} - {e.Exception?.Message}\n{e.Exception?.StackTrace}";
                
                // Log to file
                try
                {
                    string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "crash_log.txt");
                    File.AppendAllText(logPath, $"[{DateTime.Now}] {message}\n\n");
                }
                catch { }

                // Check if this is an AccessViolationException from Scylla
                if (e.Exception is AccessViolationException)
                {
                    MessageBox.Show("A memory access error occurred in Scylla.dll. The operation was aborted but the application will continue.\n\nThis can happen when the target process exits or has invalid memory.", 
                        "Scylla Memory Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
                else
                {
                    MessageBox.Show($"An error occurred:\n\n{e.Exception?.Message ?? "Unknown error"}\n\nClick OK to continue.", 
                        "MegaDumper Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
            catch { }
        }
    }
}
