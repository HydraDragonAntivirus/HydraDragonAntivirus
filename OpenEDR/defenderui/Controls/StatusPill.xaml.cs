using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace DefenderUI.Controls;

/// <summary>
/// Top bar durum rozeti (pill). Severity + Text DependencyProperty'lerine göre
/// renk ve ikonu otomatik günceller.
/// </summary>
public sealed partial class StatusPill : UserControl
{
    // ═════════════════════════════════════════════════════════════════
    // Severity DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty SeverityProperty =
        DependencyProperty.Register(
            nameof(Severity),
            typeof(StatusSeverity),
            typeof(StatusPill),
            new PropertyMetadata(StatusSeverity.Protected, OnSeverityChanged));

    public StatusSeverity Severity
    {
        get => (StatusSeverity)GetValue(SeverityProperty);
        set => SetValue(SeverityProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // Text DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty TextProperty =
        DependencyProperty.Register(
            nameof(Text),
            typeof(string),
            typeof(StatusPill),
            new PropertyMetadata("Protected", OnTextChanged));

    public string Text
    {
        get => (string)GetValue(TextProperty);
        set => SetValue(TextProperty, value);
    }

    public StatusPill()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        ApplySeverity();

        // K12: Çift abonelik korumasıyla tema değişim handler'ını bağla.
        this.ActualThemeChanged -= OnActualThemeChanged;
        this.ActualThemeChanged += OnActualThemeChanged;
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        this.ActualThemeChanged -= OnActualThemeChanged;
    }

    // Tema değişince (Light↔Dark) brush'ları yeniden uygula.
    private void OnActualThemeChanged(FrameworkElement sender, object args) => ApplySeverity();

    private static void OnSeverityChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is StatusPill pill)
        {
            pill.ApplySeverity();
        }
    }

    private static void OnTextChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is StatusPill pill && e.NewValue is string s)
        {
            pill.TextLabel.Text = s;
        }
    }

    private void ApplySeverity()
    {
        // Her severity için: (glyph, foregroundBrushKey, backgroundBrushKey)
        string glyph;
        string fgKey;
        string bgKey;

        switch (Severity)
        {
            case StatusSeverity.Warning:
                glyph = "\uE7BA"; // Warning
                fgKey = "StatusWarningBrush";
                bgKey = "StatusWarningSoftBrush";
                break;
            case StatusSeverity.Risk:
                glyph = "\uE783"; // Error / Shield exclamation
                fgKey = "StatusRiskBrush";
                bgKey = "StatusRiskSoftBrush";
                break;
            case StatusSeverity.Info:
                glyph = "\uE946"; // Info
                fgKey = "StatusInfoBrush";
                bgKey = "AccentSoftBrush";
                break;
            case StatusSeverity.Protected:
            default:
                glyph = "\uE73E"; // CheckMark
                fgKey = "StatusProtectedBrush";
                bgKey = "StatusProtectedSoftBrush";
                break;
        }

        if (IconGlyph is not null)
        {
            IconGlyph.Glyph = glyph;
            if (TryGetBrush(fgKey, out var fgBrush))
            {
                IconGlyph.Foreground = fgBrush;
                TextLabel.Foreground = fgBrush;
            }
        }

        if (PillRoot is not null && TryGetBrush(bgKey, out var bgBrush))
        {
            PillRoot.Background = bgBrush;
        }
    }

    private bool TryGetBrush(string key, out Brush brush)
    {
        // Önce kontrolün kendi resource'larına bak, yoksa Application global'e düş.
        if (Resources.TryGetValue(key, out var local) && local is Brush lb)
        {
            brush = lb;
            return true;
        }

        if (Application.Current?.Resources is not null
            && Application.Current.Resources.TryGetValue(key, out var global)
            && global is Brush gb)
        {
            brush = gb;
            return true;
        }

        brush = new SolidColorBrush(Microsoft.UI.Colors.Transparent);
        return false;
    }
}

/// <summary>
/// <see cref="StatusPill"/> severity enum.
/// </summary>
public enum StatusSeverity
{
    Protected,
    Warning,
    Risk,
    Info
}