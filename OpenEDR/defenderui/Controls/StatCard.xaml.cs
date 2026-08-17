using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace DefenderUI.Controls;

/// <summary>
/// Dashboard KPI (stat) kartı. Glyph, Label, Value, Trend ve TrendPositive
/// DP'leri ile isteğe bağlı trend rozetli küçük ölçüm kartı gösterir.
/// </summary>
public sealed partial class StatCard : UserControl
{
    // ═════════════════════════════════════════════════════════════════
    // Glyph DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty GlyphProperty =
        DependencyProperty.Register(
            nameof(Glyph),
            typeof(string),
            typeof(StatCard),
            new PropertyMetadata("\uE8F1", OnGlyphChanged));

    public string Glyph
    {
        get => (string)GetValue(GlyphProperty);
        set => SetValue(GlyphProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // Label DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty LabelProperty =
        DependencyProperty.Register(
            nameof(Label),
            typeof(string),
            typeof(StatCard),
            new PropertyMetadata(string.Empty, OnLabelChanged));

    public string Label
    {
        get => (string)GetValue(LabelProperty);
        set => SetValue(LabelProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // Value DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty ValueProperty =
        DependencyProperty.Register(
            nameof(Value),
            typeof(string),
            typeof(StatCard),
            new PropertyMetadata("0", OnValueChanged));

    public string Value
    {
        get => (string)GetValue(ValueProperty);
        set => SetValue(ValueProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // Trend DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty TrendProperty =
        DependencyProperty.Register(
            nameof(Trend),
            typeof(string),
            typeof(StatCard),
            new PropertyMetadata(null, OnTrendChanged));

    public string? Trend
    {
        get => (string?)GetValue(TrendProperty);
        set => SetValue(TrendProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // TrendPositive DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty TrendPositiveProperty =
        DependencyProperty.Register(
            nameof(TrendPositive),
            typeof(bool),
            typeof(StatCard),
            new PropertyMetadata(true, OnTrendPositiveChanged));

    public bool TrendPositive
    {
        get => (bool)GetValue(TrendPositiveProperty);
        set => SetValue(TrendPositiveProperty, value);
    }

    public StatCard()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        IconGlyph.Glyph = Glyph;
        LabelText.Text = Label;
        ValueText.Text = Value;
        ApplyTrend();

        // K12: Çift abonelik korumasıyla tema değişim handler'ını bağla.
        this.ActualThemeChanged -= OnActualThemeChanged;
        this.ActualThemeChanged += OnActualThemeChanged;
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        this.ActualThemeChanged -= OnActualThemeChanged;
    }

    // Tema değişince trend rozeti brush'larını yeniden uygula.
    private void OnActualThemeChanged(FrameworkElement sender, object args) => ApplyTrend();

    private static void OnGlyphChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is StatCard c && c.IconGlyph is not null && e.NewValue is string s)
        {
            c.IconGlyph.Glyph = s;
        }
    }

    private static void OnLabelChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is StatCard c && c.LabelText is not null && e.NewValue is string s)
        {
            c.LabelText.Text = s;
        }
    }

    private static void OnValueChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is StatCard c && c.ValueText is not null && e.NewValue is string s)
        {
            c.ValueText.Text = s;
        }
    }

    private static void OnTrendChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is StatCard c)
        {
            c.ApplyTrend();
        }
    }

    private static void OnTrendPositiveChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is StatCard c)
        {
            c.ApplyTrend();
        }
    }

    private void ApplyTrend()
    {
        if (TrendBadge is null || TrendLabel is null || TrendIcon is null)
        {
            return;
        }

        var text = Trend;
        if (string.IsNullOrWhiteSpace(text))
        {
            TrendBadge.Visibility = Visibility.Collapsed;
            return;
        }

        TrendLabel.Text = text;
        TrendBadge.Visibility = Visibility.Visible;

        string fgKey = TrendPositive ? "StatusProtectedBrush" : "StatusRiskBrush";
        string bgKey = TrendPositive ? "StatusProtectedSoftBrush" : "StatusRiskSoftBrush";
        TrendIcon.Glyph = TrendPositive ? "\uE74A" : "\uE74B"; // Up / Down chevron

        if (TryGetBrush(fgKey, out var fg))
        {
            TrendIcon.Foreground = fg;
            TrendLabel.Foreground = fg;
        }
        if (TryGetBrush(bgKey, out var bg))
        {
            TrendBadge.Background = bg;
        }
    }

    private bool TryGetBrush(string key, out Brush brush)
    {
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
        brush = new SolidColorBrush(Colors.Transparent);
        return false;
    }
}