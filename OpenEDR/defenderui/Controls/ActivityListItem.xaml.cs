using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;

namespace DefenderUI.Controls;

/// <summary>
/// "Son Aktiviteler" listesinde bir satırı temsil eden UserControl.
/// Severity'ye göre ikon rengini ve soft bg dolgusunu otomatik uygular.
/// </summary>
public sealed partial class ActivityListItem : UserControl
{
    // ═════════════════════════════════════════════════════════════════
    // Glyph DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty GlyphProperty =
        DependencyProperty.Register(
            nameof(Glyph),
            typeof(string),
            typeof(ActivityListItem),
            new PropertyMetadata("\uE946", OnGlyphChanged));

    public string Glyph
    {
        get => (string)GetValue(GlyphProperty);
        set => SetValue(GlyphProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // Severity DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty SeverityProperty =
        DependencyProperty.Register(
            nameof(Severity),
            typeof(ActivitySeverity),
            typeof(ActivityListItem),
            new PropertyMetadata(ActivitySeverity.Info, OnSeverityChanged));

    public ActivitySeverity Severity
    {
        get => (ActivitySeverity)GetValue(SeverityProperty);
        set => SetValue(SeverityProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // Title DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty TitleProperty =
        DependencyProperty.Register(
            nameof(Title),
            typeof(string),
            typeof(ActivityListItem),
            new PropertyMetadata(string.Empty, OnTitleChanged));

    public string Title
    {
        get => (string)GetValue(TitleProperty);
        set => SetValue(TitleProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // Timestamp DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty TimestampProperty =
        DependencyProperty.Register(
            nameof(Timestamp),
            typeof(string),
            typeof(ActivityListItem),
            new PropertyMetadata(string.Empty, OnTimestampChanged));

    public string Timestamp
    {
        get => (string)GetValue(TimestampProperty);
        set => SetValue(TimestampProperty, value);
    }

    public ActivityListItem()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        IconGlyph.Glyph = Glyph;
        TitleLabel.Text = Title;
        TimestampLabel.Text = Timestamp;
        ApplySeverity();

        // K12: Çift abonelik korumasıyla tema değişim handler'ını bağla.
        this.ActualThemeChanged -= OnActualThemeChanged;
        this.ActualThemeChanged += OnActualThemeChanged;
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        this.ActualThemeChanged -= OnActualThemeChanged;
    }

    // Tema değişince brush'ları re-apply et — aksi halde local-set değerler
    // eski tema snapshot'ında kalır (koyu/siyah görünüm hatası).
    private void OnActualThemeChanged(FrameworkElement sender, object args) => ApplySeverity();

    private static void OnGlyphChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ActivityListItem c && c.IconGlyph is not null && e.NewValue is string s)
        {
            c.IconGlyph.Glyph = s;
        }
    }

    private static void OnTitleChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ActivityListItem c && c.TitleLabel is not null && e.NewValue is string s)
        {
            c.TitleLabel.Text = s;
        }
    }

    private static void OnTimestampChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ActivityListItem c && c.TimestampLabel is not null && e.NewValue is string s)
        {
            c.TimestampLabel.Text = s;
        }
    }

    private static void OnSeverityChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ActivityListItem c)
        {
            c.ApplySeverity();
        }
    }

    private void ApplySeverity()
    {
        if (IconGlyph is null || IconBackground is null)
        {
            return;
        }

        string fgKey;
        string bgKey;
        switch (Severity)
        {
            case ActivitySeverity.Success:
                fgKey = "StatusProtectedBrush";
                bgKey = "StatusProtectedSoftBrush";
                break;
            case ActivitySeverity.Warning:
                fgKey = "StatusWarningBrush";
                bgKey = "StatusWarningSoftBrush";
                break;
            case ActivitySeverity.Error:
                fgKey = "StatusRiskBrush";
                bgKey = "StatusRiskSoftBrush";
                break;
            case ActivitySeverity.Info:
            default:
                fgKey = "AccentPrimaryBrush";
                bgKey = "AccentSoftBrush";
                break;
        }

        if (TryGetBrush(fgKey, out var fg))
        {
            IconGlyph.Foreground = fg;
        }
        if (TryGetBrush(bgKey, out var bg))
        {
            IconBackground.Fill = bg;
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

    private void RowRoot_PointerEntered(object sender, PointerRoutedEventArgs e)
    {
        if (TryGetBrush("SurfaceCardHoverBrush", out var b))
        {
            RowRoot.Background = b;
        }
    }

    private void RowRoot_PointerExited(object sender, PointerRoutedEventArgs e)
    {
        // Local-set değeri temizle; XAML'deki Background="Transparent"
        // ya da ThemeResource binding'i tekrar etkin olsun.
        RowRoot.ClearValue(Grid.BackgroundProperty);
    }
}

/// <summary>
/// <see cref="ActivityListItem"/> severity enum'u.
/// </summary>
public enum ActivitySeverity
{
    Info,
    Success,
    Warning,
    Error
}