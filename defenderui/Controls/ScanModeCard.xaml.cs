using System.Windows.Input;
using DefenderUI.Services;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace DefenderUI.Controls;

/// <summary>
/// Tarama modu seçim kartı (Faz 4). Glyph/Title/Description/EstimatedDuration,
/// Mode, IsSelected ve Command DP'leri ile çalışır. Seçili iken 2px accent
/// border + AccentSoft background uygular.
/// </summary>
public sealed partial class ScanModeCard : UserControl
{
    // ═════════════════════════════════════════════════════════════════
    // Glyph DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty GlyphProperty =
        DependencyProperty.Register(
            nameof(Glyph),
            typeof(string),
            typeof(ScanModeCard),
            new PropertyMetadata("\uE773", OnGlyphChanged));

    public string Glyph
    {
        get => (string)GetValue(GlyphProperty);
        set => SetValue(GlyphProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // Title DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty TitleProperty =
        DependencyProperty.Register(
            nameof(Title),
            typeof(string),
            typeof(ScanModeCard),
            new PropertyMetadata(string.Empty, OnTitleChanged));

    public string Title
    {
        get => (string)GetValue(TitleProperty);
        set => SetValue(TitleProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // Description DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty DescriptionProperty =
        DependencyProperty.Register(
            nameof(Description),
            typeof(string),
            typeof(ScanModeCard),
            new PropertyMetadata(string.Empty, OnDescriptionChanged));

    public string Description
    {
        get => (string)GetValue(DescriptionProperty);
        set => SetValue(DescriptionProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // EstimatedDuration DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty EstimatedDurationProperty =
        DependencyProperty.Register(
            nameof(EstimatedDuration),
            typeof(string),
            typeof(ScanModeCard),
            new PropertyMetadata(string.Empty, OnEstimatedDurationChanged));

    public string EstimatedDuration
    {
        get => (string)GetValue(EstimatedDurationProperty);
        set => SetValue(EstimatedDurationProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // Mode DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty ModeProperty =
        DependencyProperty.Register(
            nameof(Mode),
            typeof(ScanMode),
            typeof(ScanModeCard),
            new PropertyMetadata(ScanMode.Quick));

    public ScanMode Mode
    {
        get => (ScanMode)GetValue(ModeProperty);
        set => SetValue(ModeProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // IsSelected DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty IsSelectedProperty =
        DependencyProperty.Register(
            nameof(IsSelected),
            typeof(bool),
            typeof(ScanModeCard),
            new PropertyMetadata(false, OnIsSelectedChanged));

    public bool IsSelected
    {
        get => (bool)GetValue(IsSelectedProperty);
        set => SetValue(IsSelectedProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // Command DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty CommandProperty =
        DependencyProperty.Register(
            nameof(Command),
            typeof(ICommand),
            typeof(ScanModeCard),
            new PropertyMetadata(null));

    public ICommand? Command
    {
        get => (ICommand?)GetValue(CommandProperty);
        set => SetValue(CommandProperty, value);
    }

    public ScanModeCard()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        IconGlyph.Glyph = Glyph;
        TitleLabel.Text = Title;
        DescriptionLabel.Text = Description;
        DurationLabel.Text = EstimatedDuration;
        ApplySelection();

        // K12: Çift abonelik korumasıyla tema değişim handler'ını bağla.
        this.ActualThemeChanged -= OnActualThemeChanged;
        this.ActualThemeChanged += OnActualThemeChanged;
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        this.ActualThemeChanged -= OnActualThemeChanged;
    }

    // Tema değişince (Light↔Dark) local-set brush'lar eski temada kalmasın.
    private void OnActualThemeChanged(FrameworkElement sender, object args) => ApplySelection();

    private static void OnGlyphChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ScanModeCard c && c.IconGlyph is not null && e.NewValue is string s)
        {
            c.IconGlyph.Glyph = s;
        }
    }

    private static void OnTitleChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ScanModeCard c && c.TitleLabel is not null && e.NewValue is string s)
        {
            c.TitleLabel.Text = s;
        }
    }

    private static void OnDescriptionChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ScanModeCard c && c.DescriptionLabel is not null && e.NewValue is string s)
        {
            c.DescriptionLabel.Text = s;
        }
    }

    private static void OnEstimatedDurationChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ScanModeCard c && c.DurationLabel is not null && e.NewValue is string s)
        {
            c.DurationLabel.Text = s;
        }
    }

    private static void OnIsSelectedChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ScanModeCard c)
        {
            c.ApplySelection();
        }
    }

    private void ApplySelection()
    {
        if (CardRoot is null)
        {
            return;
        }

        if (IsSelected)
        {
            if (TryGetBrush("AccentPrimaryBrush", out var accent))
            {
                CardRoot.BorderBrush = accent;
            }
            if (TryGetBrush("AccentSoftBrush", out var soft))
            {
                CardRoot.Background = soft;
            }
            CardRoot.BorderThickness = new Thickness(2);
        }
        else
        {
            // Unselected: local-set değerleri temizle ki Style'daki
            // {ThemeResource SurfaceCardBrush} / {ThemeResource BorderSubtleBrush}
            // binding'leri yeniden aktif olsun ve tema değişimine tepki versin.
            CardRoot.ClearValue(Microsoft.UI.Xaml.Controls.Border.BackgroundProperty);
            CardRoot.ClearValue(Microsoft.UI.Xaml.Controls.Border.BorderBrushProperty);
            CardRoot.ClearValue(Microsoft.UI.Xaml.Controls.Border.BorderThicknessProperty);
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
        brush = null!;
        return false;
    }

    private void RootButton_Click(object sender, RoutedEventArgs e)
    {
        if (Command is { } cmd && cmd.CanExecute(Mode))
        {
            cmd.Execute(Mode);
        }
    }
}