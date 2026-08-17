using System;
using Microsoft.UI.Xaml;

namespace DefenderUI.Services;

/// <summary>
/// <see cref="IThemeService"/> varsayılan implementasyonu.
///
/// Kalıcılık:
///   • Paketli (MSIX) modda <c>Windows.Storage.ApplicationData.Current.LocalSettings</c>
///     kullanılır.
///   • Paketsiz çalışmada (örn. unpackaged debug) <see cref="ApplicationData"/>
///     erişimi <see cref="InvalidOperationException"/> fırlatabilir; bu durumda
///     bellek-içi (in-memory) fallback kullanılır.
///
/// Tema uygulaması:
///   • <see cref="SetTheme"/> sadece state günceller, kalıcı yazar ve event tetikler.
///   • Görsel uygulama (<see cref="FrameworkElement.RequestedTheme"/>) için
///     <see cref="ApplyTheme"/> çağrılmalıdır — bu, MainWindow'un Content root'ı
///     üzerinden tüm sayfa ağacına yansır.
/// </summary>
public sealed class ThemeService : IThemeService
{
    private const string ThemeSettingKey = "AppTheme";
    private ElementTheme _currentTheme = ElementTheme.Default;
    private FrameworkElement? _root;

    public ThemeService()
    {
        _currentTheme = LoadSavedTheme();
    }

    public ElementTheme CurrentTheme => _currentTheme;

    public event EventHandler<ElementTheme>? ThemeChanged;

    public void SetTheme(ElementTheme theme)
    {
        if (_currentTheme == theme && _root?.RequestedTheme == theme)
        {
            return;
        }

        _currentTheme = theme;
        SaveTheme(theme);

        if (_root is not null)
        {
            _root.RequestedTheme = theme;
        }

        ThemeChanged?.Invoke(this, theme);
    }

    public ElementTheme LoadSavedTheme()
    {
        try
        {
            var settings = Windows.Storage.ApplicationData.Current.LocalSettings;
            if (settings.Values.TryGetValue(ThemeSettingKey, out var value)
                && value is string s
                && Enum.TryParse<ElementTheme>(s, out var parsed))
            {
                return parsed;
            }
        }
        catch
        {
            // Unpackaged çalışmada ApplicationData erişimi başarısız olabilir;
            // sessizce default'a düş.
        }

        return ElementTheme.Default;
    }

    public void SaveTheme(ElementTheme theme)
    {
        try
        {
            var settings = Windows.Storage.ApplicationData.Current.LocalSettings;
            settings.Values[ThemeSettingKey] = theme.ToString();
        }
        catch
        {
            // Sessizce yoksay; bellek-içi state hâlâ doğru.
        }
    }

    public void ApplyTheme(FrameworkElement root)
    {
        ArgumentNullException.ThrowIfNull(root);
        _root = root;
        _root.RequestedTheme = _currentTheme;
    }
}