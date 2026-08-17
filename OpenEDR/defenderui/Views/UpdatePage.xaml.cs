using System;
using System.Windows.Input;
using DefenderUI.Models;
using DefenderUI.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace DefenderUI.Views;

public sealed partial class UpdatePage : Page
{
    public UpdateViewModel ViewModel { get; }

    public UpdatePage()
    {
        ViewModel = App.Current.Services.GetRequiredService<UpdateViewModel>();
        InitializeComponent();
        ViewModel.SetDispatcherQueue(DispatcherQueue.GetForCurrentThread());
        // Faz A #4: Tema değişiminde x:Bind static brush helper'ları otomatik
        // yeniden değerlendirilmez; ListView ItemsSource'u reset ederek
        // DataTemplate'ları yeniden üretip brush'ların yeni temayı almasını
        // sağlıyoruz.
        ActualThemeChanged += (_, _) =>
        {
            if (HistoryList is null) return;
            var src = HistoryList.ItemsSource;
            HistoryList.ItemsSource = null;
            HistoryList.ItemsSource = src;
        };
    }

    private void Page_Loaded(object sender, RoutedEventArgs e)
    {
        // Sade stil; kart stilleri hover efektlerini zaten sağlıyor.
    }

    // ═════════════════════════════════════════════════════════════════
    // Static helpers — x:Bind DataTemplate / binding içinde kullanılır.
    // ═════════════════════════════════════════════════════════════════

    public static ProtectionState GetSeverity(bool isUpdateAvailable)
        => isUpdateAvailable ? ProtectionState.AttentionNeeded : ProtectionState.Protected;

    public static string GetHeroTitle(bool isUpdateAvailable, bool isUpdating)
    {
        if (isUpdating) return "Güncelleme yükleniyor...";
        if (isUpdateAvailable) return "Yeni güncelleme mevcut";
        return "Tüm güncellemeler yüklü";
    }

    public static string GetPrimaryActionText(bool isUpdateAvailable, bool isUpdating)
    {
        if (isUpdating) return "Devam Ediyor...";
        return isUpdateAvailable ? "Şimdi Güncelle" : "Yeniden Kontrol Et";
    }

    public static ICommand? GetPrimaryCommand(UpdateViewModel vm, bool isUpdateAvailable)
        => isUpdateAvailable ? vm.StartUpdateCommand : vm.CheckForUpdatesCommand;

    public static string FormatRelative(DateTime dt)
    {
        var delta = DateTime.Now - dt;
        if (delta.TotalMinutes < 1) return "az önce";
        if (delta.TotalMinutes < 60) return $"{(int)delta.TotalMinutes} dk önce";
        if (delta.TotalHours < 24) return $"{(int)delta.TotalHours} saat önce";
        if (delta.TotalDays < 7) return $"{(int)delta.TotalDays} gün önce";
        return dt.ToString("dd MMM yyyy");
    }

    public static string FormatDate(DateTime dt)
        => dt.ToString("dd MMM yyyy · HH:mm");

    public static string OnOff(bool on) => on ? "Açık" : "Kapalı";

    public static string GetStatusGlyph(bool success) => success ? "\uE73E" : "\uE711";

    public static string GetStatusText(bool success) => success ? "Başarılı" : "Başarısız";

    public static Brush GetStatusBrush(bool success)
    {
        var key = success ? "StatusProtectedBrush" : "StatusRiskBrush";
        if (Application.Current?.Resources is not null
            && Application.Current.Resources.TryGetValue(key, out var b)
            && b is Brush brush)
        {
            return brush;
        }
        return new SolidColorBrush(Microsoft.UI.Colors.Gray);
    }
}