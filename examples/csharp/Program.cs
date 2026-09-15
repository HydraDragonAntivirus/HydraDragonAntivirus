using System;
using OpenEdr.Sdk;

namespace OpenEdrExample
{
    class Program
    {
        static void Main(string[] args)
        {
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
            Console.WriteLine();

            // 3. FLS Cloud Query
            string hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4";
            Console.WriteLine($"--- 3. Querying FLS Cloud: {hash} ---");
            var flsVerdict = scanner.QueryFls(hash);
            Console.WriteLine($"Verdict: {flsVerdict}");
        }
    }
}
