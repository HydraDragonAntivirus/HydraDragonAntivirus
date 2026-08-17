using System;
using System.Threading.Tasks;

namespace DefenderUI.Services;

public class UpdateProgressEventArgs : EventArgs
{
    public int ProgressPercent { get; set; }
    public double SpeedMbps { get; set; }
    public string StatusMessage { get; set; } = string.Empty;
}

public interface IUpdateService
{
    bool IsCheckInProgress { get; }
    Task<bool> CheckForUpdatesAsync();
    Task<bool> DownloadAndInstallUpdateAsync(Action<UpdateProgressEventArgs> progressCallback);
}
