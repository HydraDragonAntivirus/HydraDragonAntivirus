using System;
using DefenderUI.Models;
using DefenderUI.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace DefenderUI.Views;

public sealed partial class QuarantinePage : Page
{
    public QuarantineViewModel ViewModel { get; }

    public QuarantinePage()
    {
        ViewModel = App.Current.Services.GetRequiredService<QuarantineViewModel>();
        InitializeComponent();
        // Faz A #4: Tema değişiminde x:Bind static brush helper'ları otomatik
        // yeniden değerlendirilmez; ListView ItemsSource'u reset ederek tüm
        // DataTemplate'ları yeniden üretip brush'ların yeni temayı almasını
        // sağlıyoruz.
        ActualThemeChanged += (_, _) => RefreshList();
    }

    private void Page_Loaded(object sender, RoutedEventArgs e)
    {
        // Animasyonlar minimize; kart stilleri hover efektlerini zaten sağlıyor.
    }

    private void RefreshList()
    {
        if (QuarantineList is null) return;
        var src = QuarantineList.ItemsSource;
        QuarantineList.ItemsSource = null;
        QuarantineList.ItemsSource = src;
    }

    // ═════════════════════════════════════════════════════════════════
    // Static helpers — x:Bind DataTemplate içinde kullanılır.
    // ═════════════════════════════════════════════════════════════════

    public static int Sum(int a, int b) => a + b;

    public static string FormatDate(DateTime dt)
    {
        var delta = DateTime.Now - dt;
        if (delta.TotalHours < 24) return $"{(int)delta.TotalHours} saat önce";
        if (delta.TotalDays < 7) return $"{(int)delta.TotalDays} gün önce";
        return dt.ToString("dd MMM yyyy");
    }

    public static string GetRiskText(RiskLevel level) => level switch
    {
        RiskLevel.Critical => "Kritik",
        RiskLevel.High => "Yüksek",
        RiskLevel.Medium => "Orta",
        RiskLevel.Low => "Düşük",
        _ => "Bilinmiyor"
    };

    public static Brush GetRiskBrush(RiskLevel level)
    {
        var key = level switch
        {
            RiskLevel.Critical => "StatusRiskBrush",
            RiskLevel.High => "StatusRiskBrush",
            RiskLevel.Medium => "StatusWarningBrush",
            RiskLevel.Low => "AccentPrimaryBrush",
            _ => "TextTertiaryBrush"
        };

        if (Application.Current?.Resources is not null
            && Application.Current.Resources.TryGetValue(key, out var b)
            && b is Brush brush)
        {
            return brush;
        }

        return new SolidColorBrush(Microsoft.UI.Colors.Gray);
    }

    public static Brush GetRiskSoftBrush(RiskLevel level)
    {
        var key = level switch
        {
            RiskLevel.Critical => "StatusRiskSoftBrush",
            RiskLevel.High => "StatusRiskSoftBrush",
            RiskLevel.Medium => "StatusWarningSoftBrush",
            RiskLevel.Low => "AccentSoftBrush",
            _ => "SurfaceCardBrush"
        };

        if (Application.Current?.Resources is not null
            && Application.Current.Resources.TryGetValue(key, out var b)
            && b is Brush brush)
        {
            return brush;
        }

        return new SolidColorBrush(Microsoft.UI.Colors.Transparent);
    }
}