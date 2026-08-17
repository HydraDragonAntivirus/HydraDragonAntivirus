using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace DefenderUI.Services;

/// <summary>
/// <see cref="IScanService"/>'in mock asenkron implementasyonu (Faz 4).
/// Arka planda Task.Run içinde bir simülasyon döngüsü çalıştırır,
/// ~100ms'de bir <see cref="ProgressChanged"/> tetikler.
/// </summary>
public sealed class ScanService : IScanService
{
    private static readonly string[] MockPaths =
    [
        @"C:\Windows\System32\drivers\etc\hosts",
        @"C:\Windows\System32\ntdll.dll",
        @"C:\Windows\System32\kernel32.dll",
        @"C:\Windows\System32\svchost.exe",
        @"C:\Windows\System32\taskmgr.exe",
        @"C:\Windows\System32\dxgi.dll",
        @"C:\Windows\System32\wbem\WmiPrvSE.exe",
        @"C:\Windows\SysWOW64\msvcp140.dll",
        @"C:\Windows\Fonts\segoeui.ttf",
        @"C:\Program Files\Common Files\System\msadc\msadce.dll",
        @"C:\Program Files\Windows Defender\MpClient.dll",
        @"C:\Program Files\Internet Explorer\iexplore.exe",
        @"C:\Program Files\dotnet\dotnet.exe",
        @"C:\Program Files\WindowsApps\Microsoft.WindowsStore\WinStore.App.exe",
        @"C:\Program Files (x86)\Microsoft\Edge\msedge.dll",
        @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\helper.lnk",
        @"C:\Users\Default\AppData\Local\Temp\setup.exe",
        @"C:\Users\Default\Downloads\document.pdf",
        @"C:\Users\Default\Documents\report.xlsx",
        @"C:\Users\Default\Pictures\photo.jpg",
        @"D:\Backup\system-image.vhd",
        @"E:\USB\installer.exe"
    ];

    private readonly object _sync = new();
    private readonly Random _random = new();

    private CancellationTokenSource? _cts;
    private ManualResetEventSlim? _pauseGate;
    private Task? _scanTask;

    public bool IsScanning { get; private set; }
    public ScanMode? CurrentMode { get; private set; }

    public event EventHandler<ScanProgressInfo>? ProgressChanged;
    public event EventHandler<ScanCompletionInfo>? ScanCompleted;
    public event EventHandler? ScanCancelled;

    public Task StartScanAsync(ScanMode mode, IEnumerable<string>? customPaths = null)
    {
        lock (_sync)
        {
            if (IsScanning)
            {
                return Task.CompletedTask;
            }

            IsScanning = true;
            CurrentMode = mode;
            _cts = new CancellationTokenSource();
            _pauseGate = new ManualResetEventSlim(true);
        }

        var token = _cts!.Token;
        var gate = _pauseGate!;
        var totalSeconds = GetSimulatedDurationSeconds(mode);

        _scanTask = Task.Run(() => RunScanLoop(mode, totalSeconds, gate, token), token);
        return _scanTask;
    }

    public void CancelScan()
    {
        CancellationTokenSource? cts;
        ManualResetEventSlim? gate;
        lock (_sync)
        {
            if (!IsScanning)
            {
                return;
            }
            cts = _cts;
            gate = _pauseGate;
        }

        // Duraklatılmışsa cancel'ın algılanabilmesi için gate'i aç.
        gate?.Set();
        cts?.Cancel();
    }

    public void PauseScan()
    {
        lock (_sync)
        {
            if (!IsScanning)
            {
                return;
            }
            _pauseGate?.Reset();
        }
    }

    public void ResumeScan()
    {
        lock (_sync)
        {
            if (!IsScanning)
            {
                return;
            }
            _pauseGate?.Set();
        }
    }

    // ════════════════════════════════════════════════════════════════════

    private static int GetSimulatedDurationSeconds(ScanMode mode) => mode switch
    {
        ScanMode.Quick => 15,
        ScanMode.Full => 60,
        ScanMode.Custom => 20,
        ScanMode.Removable => 10,
        _ => 15
    };

    private void RunScanLoop(
        ScanMode mode,
        int totalSeconds,
        ManualResetEventSlim gate,
        CancellationToken token)
    {
        var stopwatch = Stopwatch.StartNew();
        var totalMs = totalSeconds * 1000d;
        var tickMs = 100;
        var filesScanned = 0;
        var threatsFound = 0;
        var started = DateTime.Now;
        var effectiveElapsedMs = 0d; // pause'da donduğu için real elapsed != bu

        // Planlı "sahte" tehdit tespit noktaları
        var plannedThreatPoints = mode switch
        {
            ScanMode.Full => new[] { 22d, 55d, 78d },
            ScanMode.Quick => new[] { 40d },
            ScanMode.Custom => new[] { 35d, 70d },
            ScanMode.Removable => Array.Empty<double>(),
            _ => Array.Empty<double>()
        };
        var threatIndex = 0;

        try
        {
            while (true)
            {
                if (token.IsCancellationRequested)
                {
                    break;
                }

                // Pause gate — beklerken iptal edilebilir.
                if (!gate.IsSet)
                {
                    try
                    {
                        gate.Wait(token);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                }

                Thread.Sleep(tickMs);
                if (token.IsCancellationRequested)
                {
                    break;
                }

                effectiveElapsedMs += tickMs;
                var percent = Math.Min(100d, (effectiveElapsedMs / totalMs) * 100d);

                // Dosya sayısı ~ percent ölçeklendir
                var targetFiles = (int)(percent / 100d * GetTargetFileCount(mode));
                filesScanned = Math.Max(filesScanned, targetFiles);
                filesScanned += _random.Next(3, 18);

                var currentPath = MockPaths[_random.Next(MockPaths.Length)];

                // Tehdit tespiti
                if (threatIndex < plannedThreatPoints.Length &&
                    percent >= plannedThreatPoints[threatIndex])
                {
                    threatsFound++;
                    threatIndex++;
                }

                var elapsed = TimeSpan.FromMilliseconds(effectiveElapsedMs);
                var remainingMs = Math.Max(0, totalMs - effectiveElapsedMs);
                var remaining = TimeSpan.FromMilliseconds(remainingMs);

                // U25: Event subscriber'lardan sızan exception'lar scan döngüsünü
                // bozmasın — log'layıp devam et.
                ProgressChanged?.Invoke(this, new ScanProgressInfo(
                    PercentComplete: percent,
                    FilesScanned: filesScanned,
                    ThreatsFound: threatsFound,
                    CurrentPath: currentPath,
                    Elapsed: elapsed,
                    EstimatedRemaining: remaining));

                if (percent >= 100d)
                {
                    break;
                }
            }

            stopwatch.Stop();

            if (token.IsCancellationRequested)
            {
                // K4: Event'i ResetState ÖNCESİ fire et — dinleyiciler hâlâ
                // "tarama bitiyor" state'ini görebilsin (IsScanning=true).
                ScanCancelled?.Invoke(this, EventArgs.Empty);
                ResetState();
                return;
            }

            var completion = new ScanCompletionInfo(
                Mode: mode,
                FilesScanned: filesScanned,
                ThreatsFound: threatsFound,
                Duration: TimeSpan.FromMilliseconds(effectiveElapsedMs),
                CompletedAt: DateTime.Now);

            ScanCompleted?.Invoke(this, completion);
            ResetState();
        }
        catch (OperationCanceledException)
        {
            ScanCancelled?.Invoke(this, EventArgs.Empty);
            ResetState();
        }
    }

    private static int GetTargetFileCount(ScanMode mode) => mode switch
    {
        ScanMode.Quick => 12_500,
        ScanMode.Full => 250_000,
        ScanMode.Custom => 45_000,
        ScanMode.Removable => 6_200,
        _ => 10_000
    };

    private void ResetState()
    {
        lock (_sync)
        {
            IsScanning = false;
            CurrentMode = null;
            // K4: Double-dispose guard — _cts/_pauseGate başka bir akış tarafından
            // zaten dispose edilmiş olabilir (örn. iptal+tamamlanma yarışı).
            try { _cts?.Dispose(); }
            catch (ObjectDisposedException) { /* zaten dispose */ }
            _cts = null;

            try { _pauseGate?.Dispose(); }
            catch (ObjectDisposedException) { /* zaten dispose */ }
            _pauseGate = null;
        }
    }
}