using System;
using Microsoft.UI.Xaml;

namespace DefenderUI.Services;

/// <summary>
/// Tema yönetim servisi. Light / Dark / System (Default) arası geçiş,
/// kalıcılık (ApplicationData.LocalSettings) ve <see cref="ThemeChanged"/>
/// olay akışını sağlar.
/// </summary>
public interface IThemeService
{
    /// <summary>
    /// Aktif efektif tema (<see cref="ElementTheme.Default"/> sistem temasıdır).
    /// </summary>
    ElementTheme CurrentTheme { get; }

    /// <summary>
    /// Tema her değiştiğinde tetiklenir.
    /// </summary>
    event EventHandler<ElementTheme>? ThemeChanged;

    /// <summary>
    /// Aktif temayı ayarlar ve kalıcılığa yazar.
    /// </summary>
    void SetTheme(ElementTheme theme);

    /// <summary>
    /// Önceden kaydedilmiş temayı döndürür; yoksa <see cref="ElementTheme.Default"/>.
    /// </summary>
    ElementTheme LoadSavedTheme();

    /// <summary>
    /// Seçili temayı kalıcı hale getirir (LocalSettings).
    /// </summary>
    void SaveTheme(ElementTheme theme);

    /// <summary>
    /// Verilen root FrameworkElement'e temayı uygular (XamlRoot seviyesinde).
    /// MainWindow'un content root'u için kullanılır.
    /// </summary>
    void ApplyTheme(FrameworkElement root);
}