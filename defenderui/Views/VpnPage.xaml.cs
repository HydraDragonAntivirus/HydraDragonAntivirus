using DefenderUI.Controls;
using DefenderUI.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace DefenderUI.Views;

/// <summary>
/// VPN tanıtım sayfası. Bağlantı toggle'ı ve mock sunucu listesi içerir.
/// x:Bind DataTemplate'leri için statik yardımcıları burada toplar.
/// </summary>
public sealed partial class VpnPage : Page
{
    public VpnViewModel ViewModel { get; }

    public VpnPage()
    {
        ViewModel = App.Current.Services.GetRequiredService<VpnViewModel>();
        InitializeComponent();
        // Faz A #4: Tema değişiminde x:Bind static brush helper'ları otomatik
        // yeniden değerlendirilmez; ItemsSource reset ile DataTemplate'ları
        // yeniden üretip brush'ların yeni temayı almasını sağlıyoruz.
        ActualThemeChanged += (_, _) =>
        {
            if (ServersRepeater is null) return;
            var src = ServersRepeater.ItemsSource;
            ServersRepeater.ItemsSource = null;
            ServersRepeater.ItemsSource = src;
        };
    }

    // ═══════════════════════════════════════════════════════════════════
    // Static helpers — x:Bind içinde kullanılır.
    // ═══════════════════════════════════════════════════════════════════

    /// <summary>
    /// Bağlantı durumuna göre StatusPill severity'sini döner.
    /// </summary>
    public static StatusSeverity GetPillSeverity(bool isConnected)
        => isConnected ? StatusSeverity.Protected : StatusSeverity.Warning;

    /// <summary>
    /// Büyük "Bağlan" butonunun arka plan brush'ı.
    /// </summary>
    public static Brush GetConnectBackground(bool isConnected)
    {
        var key = isConnected ? "StatusProtectedBrush" : "AccentPrimaryBrush";
        if (Application.Current?.Resources is { } res
            && res.TryGetValue(key, out var value) && value is Brush brush)
        {
            return brush;
        }
        return new SolidColorBrush(Microsoft.UI.Colors.DodgerBlue);
    }

    /// <summary>
    /// Canlı istatistikleri yalnızca bağlıyken gösterir.
    /// </summary>
    public static Visibility GetVisibility(bool isConnected)
        => isConnected ? Visibility.Visible : Visibility.Collapsed;

    /// <summary>
    /// Ping kalitesine göre rozet arka plan brush'ı.
    /// </summary>
    public static Brush GetPingBackground(PingQuality quality)
    {
        var key = quality switch
        {
            PingQuality.Good => "StatusProtectedSoftBrush",
            PingQuality.Medium => "StatusWarningSoftBrush",
            _ => "StatusRiskSoftBrush"
        };

        return ResolveBrush(key, Microsoft.UI.Colors.Transparent);
    }

    /// <summary>
    /// Ping kalitesine göre rozet yazı rengi.
    /// </summary>
    public static Brush GetPingForeground(PingQuality quality)
    {
        var key = quality switch
        {
            PingQuality.Good => "StatusProtectedBrush",
            PingQuality.Medium => "StatusWarningBrush",
            _ => "StatusRiskBrush"
        };

        return ResolveBrush(key, Microsoft.UI.Colors.Gray);
    }

    private static Brush ResolveBrush(string key, Windows.UI.Color fallback)
    {
        if (Application.Current?.Resources is { } res
            && res.TryGetValue(key, out var value) && value is Brush brush)
        {
            return brush;
        }
        return new SolidColorBrush(fallback);
    }
}