using System;
using Microsoft.Windows.AppNotifications.Builder;
using Microsoft.Windows.AppNotifications;

namespace DefenderUI.Services;

/// <summary>
/// <see cref="IToastService"/>'in varsayılan implementasyonu.
/// Windows 11 yerel Action Center bildirimlerini (Toast) de destekler.
/// </summary>
public sealed class ToastService : IToastService
{
    public event EventHandler<ToastMessage>? ToastRequested;

    public void Show(ToastMessage toast)
    {
        ArgumentNullException.ThrowIfNull(toast);
        ToastRequested?.Invoke(this, toast);
        
        try
        {
            var builder = new AppNotificationBuilder()
                .AddText(toast.Title);

            if (!string.IsNullOrWhiteSpace(toast.Body))
            {
                builder.AddText(toast.Body);
            }

            var appNotification = builder.BuildNotification();
            AppNotificationManager.Default.Show(appNotification);
        }
        catch
        {
            // Sessiz hata yönetimi
        }
    }

    public void Info(string title, string? body = null)
        => Show(new ToastMessage(title, body, ToastSeverity.Info));

    public void Success(string title, string? body = null)
        => Show(new ToastMessage(title, body, ToastSeverity.Success));

    public void Warning(string title, string? body = null)
        => Show(new ToastMessage(title, body, ToastSeverity.Warning));

    public void Error(string title, string? body = null)
        => Show(new ToastMessage(title, body, ToastSeverity.Error));
}