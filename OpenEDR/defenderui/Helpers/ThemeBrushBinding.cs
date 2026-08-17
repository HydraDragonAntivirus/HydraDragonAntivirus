using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;

namespace DefenderUI.Helpers;

/// <summary>
/// Tema-aware brush binding için attached properties.
///
/// <para>
/// THEME_AUDIT.md raporundaki "Mimari Önerisi" (sayfa sonundaki ThemeBrushBinding
/// pattern'i) uyarınca tanımlanmıştır. Tekrar eden "Application.Resources'tan
/// brush çek + local-set + ActualThemeChanged'e abone ol" kalıbını tek bir yerde
/// toplamayı amaçlar.
/// </para>
///
/// <para>
/// Her iki property de <c>string</c> brush anahtarı alır (Application.Resources
/// içinde tanımlı, ör. <c>StatusRiskBrush</c>). <see cref="FrameworkElement.ActualThemeChanged"/>
/// event'ine abone olur ve her değişimde brush'ı yeniden çözümler. Bu sayede
/// hedef element'in ilgili property'si daima güncel tema brush'ını gösterir.
/// </para>
///
/// <para>Kullanım:</para>
/// <code>
/// &lt;FontIcon helpers:ThemeBrushBinding.ForegroundKey="StatusRiskBrush" /&gt;
/// &lt;Ellipse helpers:ThemeBrushBinding.FillKey="StatusWarningSoftBrush" /&gt;
/// &lt;Border helpers:ThemeBrushBinding.BackgroundKey="SurfaceCardBrush" /&gt;
/// </code>
///
/// <para>
/// NOT: Mevcut kontroller (StatusPill, StatCard, ActivityListItem, StatusHeroCard,
/// ProtectionModuleCard vb.) zaten manuel <c>ActualThemeChanged</c> + <c>TryGetBrush</c>
/// pattern'ini başarıyla uyguladığı için re-fact edilmemiştir; bu helper ileride
/// eklenen yeni kontroller ve view'ler için alternatif olarak sunulmuştur.
/// </para>
/// </summary>
public static class ThemeBrushBinding
{
    // ──────────────────────────────────────────────────────────────
    //  ForegroundKey — TextBlock / FontIcon / Run vb.
    // ──────────────────────────────────────────────────────────────

    public static readonly DependencyProperty ForegroundKeyProperty =
        DependencyProperty.RegisterAttached(
            "ForegroundKey",
            typeof(string),
            typeof(ThemeBrushBinding),
            new PropertyMetadata(null, OnForegroundKeyChanged));

    public static string? GetForegroundKey(DependencyObject d) =>
        (string?)d.GetValue(ForegroundKeyProperty);

    public static void SetForegroundKey(DependencyObject d, string? value) =>
        d.SetValue(ForegroundKeyProperty, value);

    private static void OnForegroundKeyChanged(
        DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not FrameworkElement fe) return;

        fe.ActualThemeChanged -= OnForegroundThemeChanged;
        fe.Loaded -= OnForegroundLoaded;

        if (e.NewValue is string key && !string.IsNullOrEmpty(key))
        {
            fe.ActualThemeChanged += OnForegroundThemeChanged;
            fe.Loaded += OnForegroundLoaded;
            ApplyForeground(fe, key);
        }
    }

    private static void OnForegroundThemeChanged(FrameworkElement sender, object args)
    {
        var key = GetForegroundKey(sender);
        if (!string.IsNullOrEmpty(key)) ApplyForeground(sender, key);
    }

    private static void OnForegroundLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe)
        {
            var key = GetForegroundKey(fe);
            if (!string.IsNullOrEmpty(key)) ApplyForeground(fe, key);
        }
    }

    private static void ApplyForeground(FrameworkElement fe, string key)
    {
        if (!TryResolveBrush(key, out var brush)) return;

        switch (fe)
        {
            case TextBlock tb: tb.Foreground = brush; break;
            case FontIcon fi: fi.Foreground = brush; break;
            case Control c: c.Foreground = brush; break;
            case ContentPresenter cp: cp.Foreground = brush; break;
        }
    }

    // ──────────────────────────────────────────────────────────────
    //  BackgroundKey — Border / Panel / Control
    // ──────────────────────────────────────────────────────────────

    public static readonly DependencyProperty BackgroundKeyProperty =
        DependencyProperty.RegisterAttached(
            "BackgroundKey",
            typeof(string),
            typeof(ThemeBrushBinding),
            new PropertyMetadata(null, OnBackgroundKeyChanged));

    public static string? GetBackgroundKey(DependencyObject d) =>
        (string?)d.GetValue(BackgroundKeyProperty);

    public static void SetBackgroundKey(DependencyObject d, string? value) =>
        d.SetValue(BackgroundKeyProperty, value);

    private static void OnBackgroundKeyChanged(
        DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not FrameworkElement fe) return;

        fe.ActualThemeChanged -= OnBackgroundThemeChanged;
        fe.Loaded -= OnBackgroundLoaded;

        if (e.NewValue is string key && !string.IsNullOrEmpty(key))
        {
            fe.ActualThemeChanged += OnBackgroundThemeChanged;
            fe.Loaded += OnBackgroundLoaded;
            ApplyBackground(fe, key);
        }
    }

    private static void OnBackgroundThemeChanged(FrameworkElement sender, object args)
    {
        var key = GetBackgroundKey(sender);
        if (!string.IsNullOrEmpty(key)) ApplyBackground(sender, key);
    }

    private static void OnBackgroundLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement fe)
        {
            var key = GetBackgroundKey(fe);
            if (!string.IsNullOrEmpty(key)) ApplyBackground(fe, key);
        }
    }

    private static void ApplyBackground(FrameworkElement fe, string key)
    {
        if (!TryResolveBrush(key, out var brush)) return;

        switch (fe)
        {
            case Border b: b.Background = brush; break;
            case Panel p: p.Background = brush; break;
            case Control c: c.Background = brush; break;
            case ContentPresenter cp: cp.Background = brush; break;
        }
    }

    // ──────────────────────────────────────────────────────────────
    //  FillKey — Shape (Ellipse, Rectangle, Path, ...)
    // ──────────────────────────────────────────────────────────────

    public static readonly DependencyProperty FillKeyProperty =
        DependencyProperty.RegisterAttached(
            "FillKey",
            typeof(string),
            typeof(ThemeBrushBinding),
            new PropertyMetadata(null, OnFillKeyChanged));

    public static string? GetFillKey(DependencyObject d) =>
        (string?)d.GetValue(FillKeyProperty);

    public static void SetFillKey(DependencyObject d, string? value) =>
        d.SetValue(FillKeyProperty, value);

    private static void OnFillKeyChanged(
        DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not Shape shape) return;

        shape.ActualThemeChanged -= OnFillThemeChanged;
        shape.Loaded -= OnFillLoaded;

        if (e.NewValue is string key && !string.IsNullOrEmpty(key))
        {
            shape.ActualThemeChanged += OnFillThemeChanged;
            shape.Loaded += OnFillLoaded;
            ApplyFill(shape, key);
        }
    }

    private static void OnFillThemeChanged(FrameworkElement sender, object args)
    {
        if (sender is Shape shape)
        {
            var key = GetFillKey(shape);
            if (!string.IsNullOrEmpty(key)) ApplyFill(shape, key);
        }
    }

    private static void OnFillLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is Shape shape)
        {
            var key = GetFillKey(shape);
            if (!string.IsNullOrEmpty(key)) ApplyFill(shape, key);
        }
    }

    private static void ApplyFill(Shape shape, string key)
    {
        if (TryResolveBrush(key, out var brush))
        {
            shape.Fill = brush;
        }
    }

    // ──────────────────────────────────────────────────────────────
    //  Ortak brush çözümleyici
    // ──────────────────────────────────────────────────────────────

    private static bool TryResolveBrush(string key, out Brush brush)
    {
        if (Application.Current?.Resources is { } res
            && res.TryGetValue(key, out var value)
            && value is Brush b)
        {
            brush = b;
            return true;
        }
        brush = null!;
        return false;
    }
}