using System;
using OpenEdr.Sdk;

namespace OpenEdrExample
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "daemon")
            {
                RunDaemon(args.Length > 1 ? args[1] : null);
                return;
            }

            Console.WriteLine("[*] Initializing OpenEDR Scanner in C# .NET...");
            using var scanner = new OpenEdrScanner("OpenMalwareScannerPortable");
            Console.WriteLine("[+] Scanner Initialized Successfully!\n");

            // 1. File Scan
            string target = "OpenMalwareScannerPortable/openedr_static.dll";
            Console.WriteLine($"--- 1. Scanning File: {target} ---");
            string report = scanner.ScanFile(target);
            Console.WriteLine(report);
            Console.WriteLine();

            // 2. URL Scan
            string url = "https://phishing-site-example.com/login";
            Console.WriteLine($"--- 2. Scanning URL: {url} ---");
            string urlReport = scanner.ScanUrl(url);
            Console.WriteLine(urlReport);
        }

        // dotnet run -- daemon [watchDir]
        static void RunDaemon(string dir)
        {
            dir ??= Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            using var scanner = new OpenEdrScanner("OpenMalwareScannerPortable");
            using var daemon = new DaemonWatcher(
                scanner, dir,
                onHit: (path, verdict) => Console.WriteLine($"[!] {verdict} :: {path}"));
            daemon.Start();
            Console.WriteLine($"[*] Watching {dir} - Ctrl+C to stop");
            using var done = new ManualResetEventSlim(false);
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; done.Set(); };
            done.Wait();
            Console.WriteLine($"[*] Stopped. scanned={daemon.Scanned} hits={daemon.Hits} cached={daemon.SkippedCache}");
        }
    }
}
