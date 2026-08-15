using System;
using System.Runtime.InteropServices;
using DefenderUI.Helpers;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace DefenderUI.Views;

/// <summary>
/// Gerçek zamanlı koruma bir tehdit tespit ettiğinde gösterilen, ekranın sağ
/// alt köşesinde çerçevesiz açılan küçük bildirim kartı. EDR tarafı
/// `--threat-alert` komut satırı argümanı ile açılır.
/// Kırmızı çerçeve = tehdit, turuncu çerçeve = şüpheli davranış.
/// </summary>
public sealed partial class ThreatAlertWindow : Window
{
    private const uint EWX_REBOOT = 0x00000002;
    private const uint SHTDN_REASON_MAJOR_OTHER = 0x00000000;
    private const uint SHTDN_REASON_FLAG_PLANNED = 0x80000000;

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ExitWindowsEx(uint uFlags, uint dwReason);

    private const int CardWidth = 440;
    private const int CardHeight = 230;

    public string ThreatName { get; }
    public string FilePath { get; }
    public string Severity { get; }

    private readonly Action? _onDeleteNow;

    public ThreatAlertWindow(
        string threatName,
        string filePath,
        string severity,
        Action? onDeleteNow = null)
    {
        ThreatName = threatName;
        FilePath = filePath;
        Severity = severity;
        _onDeleteNow = onDeleteNow;

        InitializeComponent();
        Title = "HydraDragonAntivirus - Threat Detected";

        ApplySeverityStyle(severity);
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

    /// <summary>
    /// Çerçeve ve durum metnini severity'e göre renklendirir:
    /// Critical/High → kırmızı, Medium/Low → turuncu.
    /// </summary>
    private void ApplySeverityStyle(string severity)
    {
        var isRisk = !string.Equals(severity, "Medium", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(severity, "Low", StringComparison.OrdinalIgnoreCase);

        var frameColor = isRisk ? Color.FromArgb(0xFF, 0xD1, 0x34, 0x38) : Color.FromArgb(0xFF, 0xF7, 0xB5, 0x00);
        var softColor = isRisk ? Color.FromArgb(0xFF, 0xFD, 0xE7, 0xE9) : Color.FromArgb(0xFF, 0xFF, 0xF4, 0xCE);
        var text = isRisk ? "THREAT DETECTED" : "SUSPICIOUS";

        AlertFrame.BorderBrush = new SolidColorBrush(frameColor);
        HeaderStatusText.Foreground = new SolidColorBrush(frameColor);
        HeaderStatusText.Text = text;
        HeaderStatusBadge.Background = new SolidColorBrush(softColor);
        ThreatNameText.Foreground = new SolidColorBrush(frameColor);
    }

    private void DeleteNowButton_Click(object sender, RoutedEventArgs e)
    {
        _onDeleteNow?.Invoke();
        Close();
    }

    private void RestartButton_Click(object sender, RoutedEventArgs e)
    {
        var result = ExitWindowsEx(EWX_REBOOT, SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_FLAG_PLANNED);
        if (result is false)
        {
            Close();
        }
    }
}