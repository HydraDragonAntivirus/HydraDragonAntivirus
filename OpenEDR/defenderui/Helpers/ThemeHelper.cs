using System;
using System.Reflection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Media;

namespace DefenderUI.Helpers;

/// <summary>
/// Tema ile ilgili saf (framework-bağımsız) yardımcı fonksiyonlar.
///
/// <see cref="Services.IThemeService"/> uygulama-genelinde durum tutar ve
/// MainWindow root'una bağlıdır; bu helper ise tek seferlik dönüşümler için
/// kullanılır (ör. string → ElementTheme parse, popup/ContentDialog gibi ayrı
/// visual tree'lere tema uygulama).
/// </summary>
public static class ThemeHelper
{
    /// <summary>
    /// Verilen string'i <see cref="ElementTheme"/>'e parse eder. Geçersiz veya
    /// boş giriş için <see cref="ElementTheme.Default"/> döner.
    /// </summary>
    public static ElementTheme GetElementThemeFromString(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return ElementTheme.Default;
        }

        return Enum.TryParse<ElementTheme>(value, ignoreCase: true, out var parsed)
            ? parsed
            : ElementTheme.Default;
    }

    /// <summary>
    /// Verilen <see cref="FrameworkElement"/>'e tema uygular. Null-güvenli.
    /// </summary>
    public static void ApplyThemeToElement(FrameworkElement? element, ElementTheme theme)
    {
        if (element is null) return;
        element.RequestedTheme = theme;
    }

    /// <summary>
    /// Faz D #20: <see cref="FlyoutBase"/> (MenuFlyout, Flyout, CommandBarFlyout)
    /// Popup olarak açıldığında visual tree'den bağımsız olduğu için
    /// <see cref="FrameworkElement.ActualTheme"/>'yi miras almaz. Bu metot
    /// flyout'un <see cref="FlyoutBase.RequestedTheme"/>'ini verilen sahiple
    /// eşler; sahibin tema değişimini de dinleyerek yansıtır.
    /// </summary>
    public static void SyncFlyoutTheme(FlyoutBase? flyout, FrameworkElement? owner)
    {
        if (flyout is null || owner is null) return;
        TrySetFlyoutRequestedTheme(flyout, owner.ActualTheme);
        owner.ActualThemeChanged -= OwnerThemeChangedHandler;
        owner.ActualThemeChanged += OwnerThemeChangedHandler;

        void OwnerThemeChangedHandler(FrameworkElement s, object e)
        {
            TrySetFlyoutRequestedTheme(flyout, s.ActualTheme);
        }
    }

    // WindowsAppSDK 1.8 itibariyle FlyoutBase.RequestedTheme C# yüzeyinden
    // doğrudan görünmeyebiliyor (CS1061). Aynı property türetilmiş
    // sınıflarda (Flyout/MenuFlyout/CommandBarFlyout) WinRT projeksiyonu
    // ile mevcut olduğundan reflection üzerinden güvenli biçimde set
    // ediyoruz. Bulunamazsa davranış no-op olur (popup tema senkronu
    // sessizce devre dışı kalır), build veya runtime kırılmaz.
    private static PropertyInfo? _flyoutRequestedThemeProp;
    private static bool _flyoutRequestedThemeProbed;

    private static void TrySetFlyoutRequestedTheme(FlyoutBase flyout, ElementTheme theme)
    {
        try
        {
            var type = flyout.GetType();
            if (!_flyoutRequestedThemeProbed || _flyoutRequestedThemeProp?.DeclaringType != type)
            {
                _flyoutRequestedThemeProp = type.GetProperty(
                    "RequestedTheme",
                    BindingFlags.Public | BindingFlags.Instance);
                _flyoutRequestedThemeProbed = true;
            }

            _flyoutRequestedThemeProp?.SetValue(flyout, theme);
        }
        catch
        {
            // Tema senkronu kritik değil; sessizce yut.
        }
    }

    // ──────────────────────────────────────────────────────────────
    //  Faz D #20: Attached property — Button gibi FlyoutBase sahibi
    //  element'in ActualTheme'ini Flyout'a otomatik yansıt.
    //  XAML kullanımı:
    //    <Button helpers:ThemeHelper.SyncFlyoutTheme="True" ...>
    //        <Button.Flyout>
    //            <MenuFlyout> ... </MenuFlyout>
    //        </Button.Flyout>
    //    </Button>
    // ──────────────────────────────────────────────────────────────

    public static readonly DependencyProperty SyncFlyoutThemeProperty =
        DependencyProperty.RegisterAttached(
            "SyncFlyoutTheme",
            typeof(bool),
            typeof(ThemeHelper),
            new PropertyMetadata(false, OnSyncFlyoutThemeChanged));

    public static bool GetSyncFlyoutTheme(DependencyObject obj) =>
        (bool)obj.GetValue(SyncFlyoutThemeProperty);

    public static void SetSyncFlyoutTheme(DependencyObject obj, bool value) =>
        obj.SetValue(SyncFlyoutThemeProperty, value);

    private static void OnSyncFlyoutThemeChanged(
        DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not FrameworkElement fe) return;
        if (e.NewValue is bool enabled && enabled)
        {
            fe.Loaded -= FlyoutOwnerLoaded;
            fe.Loaded += FlyoutOwnerLoaded;
            // Zaten Loaded olmuşsa hemen uygula.
            TryApplyFlyoutTheme(fe);
        }
    }

    private static void FlyoutOwnerLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe)
        {
            TryApplyFlyoutTheme(fe);
        }
    }

    private static void TryApplyFlyoutTheme(FrameworkElement fe)
    {
        var flyout = fe switch
        {
            Button b => b.Flyout,
            _ => FlyoutBase.GetAttachedFlyout(fe),
        };
        SyncFlyoutTheme(flyout, fe);
    }
}