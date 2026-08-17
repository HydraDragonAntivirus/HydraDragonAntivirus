using System;

namespace DefenderUI.Services;

public interface IScheduledScanService
{
    bool IsRunning { get; }
    void StartScheduler();
    void StopScheduler();
    event EventHandler<string>? ScheduledScanTriggered;
}
