using System;
using System.Diagnostics;
using System.IO;

namespace DefenderUI.Services;

/// <summary>
/// edrsvc.exe (EDR servisi) üzerinde start/stop komutlarını çalıştırır.
/// edrsvc'yi önce uygulamanın yanında, sonra varsayılan kurulum yolunda arar.
/// </summary>
public static class EdrServiceController
{
    private const string EdrSvcName = "edrsvc.exe";

    /// <summary>
    /// edrsvc.exe'nin yolunu bulur; bulunamazsa varsayılan yol adaylarını döner.
    /// </summary>
    public static string? ResolveEdrSvcPath()
    {
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, EdrSvcName),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "HydraDragonAntivirus", EdrSvcName),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "HydraDragonAntivirus", EdrSvcName),
        };

        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    public static void Start()
        => RunCommand("start");

    public static void Stop()
        => RunCommand("stop");

    private static void RunCommand(string verb)
    {
        var path = ResolveEdrSvcPath();
        if (path is null)
        {
            return;
        }

        try
        {
            var psi = new ProcessStartInfo(path, verb)
            {
                UseShellExecute = true,
                Verb = "runas",
                CreateNoWindow = true,
            };
            Process.Start(psi);
        }
        catch
        {
            // Yükseltme iptal edildi veya başlatılamadı — sessiz geç.
        }
    }
}