using System;
using DefenderUI.Helpers;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace DefenderUI.Views;

/// <summary>
/// Gerçek zamanlı koruma bir tehdidi otomatik karantinaya aldığında gösterilen,
/// ekranın sağ alt köşesinde çerçevesiz açılan küçük bildirim kartı.
/// EDR tarafı `--threat-alert` komut satırı argümanı ile açılır.
/// </summary>
public sealed partial class ThreatAlertWindow : Window
{
    private const int CardWidth = 480;
    private const int CardHeight = 260;

    public string ThreatName { get; }
    public string FilePath { get; }

    public ThreatAlertWindow(string threatName, string filePath)
    {
        ThreatName = threatName;
        FilePath = filePath;

        InitializeComponent();
        Title = "HydraDragonAntivirus - Threat Quarantined";

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

    private void OkButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}