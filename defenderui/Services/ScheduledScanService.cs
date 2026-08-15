using System;
using System.Threading;
using System.Threading.Tasks;

namespace DefenderUI.Services;

public class ScheduledScanService : IScheduledScanService, IDisposable
{
    private readonly ISettingsService _settingsService;
    private readonly IToastService _toastService;
    private PeriodicTimer? _timer;
    private CancellationTokenSource? _cts;

    public bool IsRunning { get; private set; }
    public event EventHandler<string>? ScheduledScanTriggered;

    public ScheduledScanService(ISettingsService settingsService, IToastService toastService)
    {
        _settingsService = settingsService;
        _toastService = toastService;
        if (_settingsService.CurrentSettings.ScheduledScanEnabled)
        {
            StartScheduler();
        }
    }

    public void StartScheduler()
    {
        if (IsRunning) return;

        IsRunning = true;
        _cts = new CancellationTokenSource();
        _timer = new PeriodicTimer(TimeSpan.FromMinutes(60)); // Check every hour

        _ = Task.Run(async () =>
        {
            try
            {
                while (await _timer.WaitForNextTickAsync(_cts.Token))
                {
                    if (_settingsService.CurrentSettings.ScheduledScanEnabled)
                    {
                        var scanType = _settingsService.CurrentSettings.ScheduledScanType;
                        ScheduledScanTriggered?.Invoke(this, scanType);
                        _toastService.Info("Zamanlanmış Tarama", $"Otomatik {scanType} arka planda başlatıldı.");
                    }
                }
            }
            catch (OperationCanceledException) { }
        });
    }

    public void StopScheduler()
    {
        IsRunning = false;
        _cts?.Cancel();
        _timer?.Dispose();
        _timer = null;
    }

    public void Dispose()
    {
        StopScheduler();
    }
}
