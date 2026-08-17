using System;
using System.Threading.Tasks;

namespace DefenderUI.Services;

public class UpdateService : IUpdateService
{
    public bool IsCheckInProgress { get; private set; }

    public async Task<bool> CheckForUpdatesAsync()
    {
        IsCheckInProgress = true;
        await Task.Delay(1200);
        IsCheckInProgress = false;
        return true;
    }

    public async Task<bool> DownloadAndInstallUpdateAsync(Action<UpdateProgressEventArgs> progressCallback)
    {
        for (int p = 0; p <= 100; p += 10)
        {
            await Task.Delay(200);
            progressCallback(new UpdateProgressEventArgs
            {
                ProgressPercent = p,
                SpeedMbps = 12.5 + (p % 3),
                StatusMessage = p < 100 ? $"İmza veritabanı indiriliyor... (%{p})" : "Güncelleme başarıyla uygulandı."
            });
        }
        return true;
    }
}
