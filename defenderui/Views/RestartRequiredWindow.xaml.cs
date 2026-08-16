using System;
using System.Runtime.InteropServices;
using DefenderUI.Helpers;
using Microsoft.UI.Xaml;

namespace DefenderUI.Views;

/// <summary>
/// Restart gerektiren durumlar için gösterilen, ekranın sağ alt köşesinde
/// çerçevesiz açılan küçük bildirim kartı. İki kullanımı vardır:
///  * karantina temizliği (dosya kullanımda — varsayılan metin),
///  * MBRFilter sürücü kurulumu (`--message` / `--submessage` ile özelleştirilir).
/// EDR tarafı `--restart-required` komut satırı argümanı ile açılır.
/// </summary>
public sealed partial class RestartRequiredWindow : Window
{
    private const uint EWX_REBOOT = 0x00000002;
    private const uint SHTDN_REASON_MAJOR_OTHER = 0x00000000;
    private const uint SHTDN_REASON_FLAG_PLANNED = 0x80000000;

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ExitWindowsEx(uint uFlags, uint dwReason);

    private const int CardWidth = 480;
    private const int CardHeight = 260;

    public string FilePath { get; }
    public string Message { get; }
    public string SubMessage { get; }

    public RestartRequiredWindow(string filePath, string? message = null, string? subMessage = null)
    {
        FilePath = filePath;
        Message = string.IsNullOrEmpty(message)
            ? "A threat could not be removed while in use."
            : message;
        SubMessage = string.IsNullOrEmpty(subMessage)
            ? "The file will be cleaned up after a restart."
            : subMessage;
        InitializeComponent();
        Title = "HydraDragonAntivirus - Restart Required";

        TrayNotificationWindow.PositionBottomRight(this, CardWidth, CardHeight);

        try
        {
            AppWindow.SetIcon("Assets/AppIcon.ico");
        }
        catch
        {
            // Unpackaged çalışmada fail olabilir; kritik değil.
        }
    }

    private void RestartButton_Click(object sender, RoutedEventArgs e)
    {
        var result = ExitWindowsEx(EWX_REBOOT, SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_FLAG_PLANNED);
        if (result is false)
        {
            Close();
        }
    }

    private void LaterButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}