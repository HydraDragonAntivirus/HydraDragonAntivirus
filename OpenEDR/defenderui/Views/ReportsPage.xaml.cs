using System;
using DefenderUI.Models;
using DefenderUI.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DefenderUI.Views;

public sealed partial class ReportsPage : Page
{
    public ReportsViewModel ViewModel { get; }

    public ReportsPage()
    {
        ViewModel = App.Current.Services.GetRequiredService<ReportsViewModel>();
        InitializeComponent();
    }

    private void Page_Loaded(object sender, RoutedEventArgs e)
    {
        // Sade stil; hover ve kart stilleri ekranı zaten canlandırıyor.
    }

    // ═════════════════════════════════════════════════════════════════
    // Static helpers — x:Bind DataTemplate içinde kullanılır.
    // ═════════════════════════════════════════════════════════════════

    private const double MaxBarHeight = 160.0;

    public static double BarHeight(int value, int max)
    {
        if (max <= 0) return 4;
        var ratio = Math.Clamp(value / (double)max, 0.04, 1.0);
        return ratio * MaxBarHeight;
    }

    public static string GetScanTypeText(ScanType type) => type switch
    {
        ScanType.Quick => "Hızlı",
        ScanType.Full => "Tam",
        ScanType.Custom => "Özel",
        ScanType.USB => "USB",
        _ => "Bilinmiyor"
    };

    public static string FormatDate(DateTime dt)
    {
        return dt.ToString("dd MMM yyyy · HH:mm");
    }

    public static string FormatDuration(TimeSpan duration)
    {
        if (duration.TotalHours >= 1)
        {
            return $"{(int)duration.TotalHours}s {duration.Minutes}dk";
        }
        if (duration.TotalMinutes >= 1)
        {
            return $"{duration.Minutes}dk {duration.Seconds}sn";
        }
        return $"{duration.Seconds}sn";
    }
}