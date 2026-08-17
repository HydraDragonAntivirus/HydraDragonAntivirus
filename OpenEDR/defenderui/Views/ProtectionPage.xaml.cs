using System;
using DefenderUI.Controls;
using DefenderUI.Models;
using DefenderUI.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DefenderUI.Views;

/// <summary>
/// Protection sayfası (Faz 5 — Kaspersky tarzı refactor).
/// MVVM odaklı; code-behind yalnızca DI ve x:Bind için saf yardımcı metodları barındırır.
/// </summary>
public sealed partial class ProtectionPage : Page
{
    public ProtectionViewModel ViewModel { get; }

    public ProtectionPage()
    {
        ViewModel = App.Current.Services.GetRequiredService<ProtectionViewModel>();
        InitializeComponent();
    }

    private void Page_Loaded(object sender, RoutedEventArgs e)
    {
        // Faz 5'te sayfa entrance animasyonları yeni tasarımla uyumlu olmadığı için
        // daha sade durum — hover/lift zaten kart stillerinde var.
    }

    // ═════════════════════════════════════════════════════════════════
    // Static helpers — x:Bind DataTemplate içinde kullanılır.
    // ═════════════════════════════════════════════════════════════════

    public static string GetActivityGlyph(ActivityType type) => type switch
    {
        ActivityType.ThreatBlocked => "\uE730",
        ActivityType.ScanCompleted => "\uE73E",
        ActivityType.DatabaseUpdated => "\uE895",
        ActivityType.FileQuarantined => "\uE7B8",
        ActivityType.ProtectionEnabled => "\uE72E",
        ActivityType.ProtectionDisabled => "\uE7BA",
        ActivityType.Warning => "\uE7BA",
        _ => "\uE946"
    };

    public static ActivitySeverity GetActivitySeverity(ActivityType type) => type switch
    {
        ActivityType.ThreatBlocked => ActivitySeverity.Error,
        ActivityType.ScanCompleted => ActivitySeverity.Success,
        ActivityType.DatabaseUpdated => ActivitySeverity.Info,
        ActivityType.FileQuarantined => ActivitySeverity.Warning,
        ActivityType.ProtectionEnabled => ActivitySeverity.Success,
        ActivityType.ProtectionDisabled => ActivitySeverity.Warning,
        ActivityType.Warning => ActivitySeverity.Warning,
        _ => ActivitySeverity.Info
    };

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