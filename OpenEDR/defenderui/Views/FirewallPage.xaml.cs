using System;
using DefenderUI.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace DefenderUI.Views;

/// <summary>
/// Güvenlik duvarı sayfası. x:Bind içindeki DataTemplate'ler için statik
/// yardımcı metodları barındırır.
/// </summary>
public sealed partial class FirewallPage : Page
{
    public FirewallViewModel ViewModel { get; }

    public FirewallPage()
    {
        ViewModel = App.Current.Services.GetRequiredService<FirewallViewModel>();
        InitializeComponent();
        // Faz A #4: Tema değişiminde x:Bind static brush helper'ları otomatik
        // yeniden değerlendirilmez; ItemsSource reset ile DataTemplate'ları
        // yeniden üretip brush'ların yeni temayı almasını sağlıyoruz.
        ActualThemeChanged += (_, _) =>
        {
            RefreshRepeater(RulesRepeater);
            RefreshRepeater(RecentBlocksRepeater);
        };
    }

    private static void RefreshRepeater(Microsoft.UI.Xaml.Controls.ItemsRepeater? rep)
    {
        if (rep is null) return;
        var src = rep.ItemsSource;
        rep.ItemsSource = null;
        rep.ItemsSource = src;
    }

    /// <summary>
    /// Kural "İzin Ver" ise soft yeşil, "Engelle" ise soft kırmızı arka plan döner.
    /// </summary>
    public static Brush GetActionBrush(bool isAllow)
    {
        var key = isAllow ? "StatusProtectedSoftBrush" : "StatusRiskSoftBrush";
        if (Microsoft.UI.Xaml.Application.Current?.Resources is { } res
            && res.TryGetValue(key, out var value) && value is Brush brush)
        {
            return brush;
        }
        return new SolidColorBrush(Microsoft.UI.Colors.Transparent);
    }

    /// <summary>
    /// Kural "İzin Ver" ise yeşil, "Engelle" ise kırmızı yazı rengi döner.
    /// </summary>
    public static Brush GetActionForeground(bool isAllow)
    {
        var key = isAllow ? "StatusProtectedBrush" : "StatusRiskBrush";
        if (Microsoft.UI.Xaml.Application.Current?.Resources is { } res
            && res.TryGetValue(key, out var value) && value is Brush brush)
        {
            return brush;
        }
        return new SolidColorBrush(Microsoft.UI.Colors.Gray);
    }

    public static string FormatRelativeTime(DateTime timestamp)
    {
        var delta = DateTime.Now - timestamp;
        if (delta.TotalMinutes < 1) return "az önce";
        if (delta.TotalMinutes < 60) return $"{(int)delta.TotalMinutes} dakika önce";
        if (delta.TotalHours < 24) return $"{(int)delta.TotalHours} saat önce";
        if (delta.TotalDays < 7) return $"{(int)delta.TotalDays} gün önce";
        return timestamp.ToString("dd MMM yyyy");
    }
}