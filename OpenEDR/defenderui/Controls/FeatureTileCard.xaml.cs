using System.Windows.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace DefenderUI.Controls;

/// <summary>
/// Dashboard "Hızlı Eylemler" grid'inde kullanılan feature tile kartı.
/// Glyph, Title, Description, AccentBrush, BadgeText ve Command DP'lerine sahiptir.
/// Tıklanınca <see cref="Command"/> <see cref="CommandParameter"/> ile çalıştırılır.
/// </summary>
public sealed partial class FeatureTileCard : UserControl
{
    // ═════════════════════════════════════════════════════════════════
    // Glyph DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty GlyphProperty =
        DependencyProperty.Register(
            nameof(Glyph),
            typeof(string),
            typeof(FeatureTileCard),
            new PropertyMetadata("\uE72E", OnGlyphChanged));

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
            typeof(FeatureTileCard),
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
            typeof(FeatureTileCard),
            new PropertyMetadata(string.Empty, OnDescriptionChanged));

    public string Description
    {
        get => (string)GetValue(DescriptionProperty);
        set => SetValue(DescriptionProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // ActionText DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty ActionTextProperty =
        DependencyProperty.Register(
            nameof(ActionText),
            typeof(string),
            typeof(FeatureTileCard),
            new PropertyMetadata("Aç", OnActionTextChanged));

    public string ActionText
    {
        get => (string)GetValue(ActionTextProperty);
        set => SetValue(ActionTextProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // AccentBrush DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty AccentBrushProperty =
        DependencyProperty.Register(
            nameof(AccentBrush),
            typeof(Brush),
            typeof(FeatureTileCard),
            new PropertyMetadata(null, OnAccentBrushChanged));

    public Brush? AccentBrush
    {
        get => (Brush?)GetValue(AccentBrushProperty);
        set => SetValue(AccentBrushProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // BadgeText DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty BadgeTextProperty =
        DependencyProperty.Register(
            nameof(BadgeText),
            typeof(string),
            typeof(FeatureTileCard),
            new PropertyMetadata(null, OnBadgeTextChanged));

    public string? BadgeText
    {
        get => (string?)GetValue(BadgeTextProperty);
        set => SetValue(BadgeTextProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // Command DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty CommandProperty =
        DependencyProperty.Register(
            nameof(Command),
            typeof(ICommand),
            typeof(FeatureTileCard),
            new PropertyMetadata(null));

    public ICommand? Command
    {
        get => (ICommand?)GetValue(CommandProperty);
        set => SetValue(CommandProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // CommandParameter DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty CommandParameterProperty =
        DependencyProperty.Register(
            nameof(CommandParameter),
            typeof(object),
            typeof(FeatureTileCard),
            new PropertyMetadata(null));

    public object? CommandParameter
    {
        get => GetValue(CommandParameterProperty);
        set => SetValue(CommandParameterProperty, value);
    }

    public FeatureTileCard()
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
        ActionTextLabel.Text = ActionText;
        ApplyAccent();
        ApplyBadge();

        // K12: Çift abonelik korumasıyla tema değişim handler'ını bağla.
        this.ActualThemeChanged -= OnActualThemeChanged;
        this.ActualThemeChanged += OnActualThemeChanged;
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        this.ActualThemeChanged -= OnActualThemeChanged;
    }

    // Faz A #3: Tema değişiminde accent brush'u yeniden uygula. AccentBrush DP
    // set edilmemişse ApplyAccent ClearValue çağırarak XAML'deki ThemeResource
    // binding'ini geri yükler — bu da otomatik olarak yeni tema rengine geçer.
    private void OnActualThemeChanged(FrameworkElement sender, object args) => ApplyAccent();

    private static void OnGlyphChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is FeatureTileCard c && c.IconGlyph is not null && e.NewValue is string s)
        {
            c.IconGlyph.Glyph = s;
        }
    }

    private static void OnTitleChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is FeatureTileCard c && c.TitleLabel is not null && e.NewValue is string s)
        {
            c.TitleLabel.Text = s;
        }
    }

    private static void OnDescriptionChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is FeatureTileCard c && c.DescriptionLabel is not null && e.NewValue is string s)
        {
            c.DescriptionLabel.Text = s;
        }
    }

    private static void OnActionTextChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is FeatureTileCard c && c.ActionTextLabel is not null && e.NewValue is string s)
        {
            c.ActionTextLabel.Text = s;
        }
    }

    private static void OnAccentBrushChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is FeatureTileCard c)
        {
            c.ApplyAccent();
        }
    }

    private static void OnBadgeTextChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is FeatureTileCard c)
        {
            c.ApplyBadge();
        }
    }

    private void ApplyAccent()
    {
        if (IconGlyph is null || ActionTextLabel is null)
        {
            return;
        }

        // Faz A #3: AccentBrush DP açıkça set edilmişse override uygula.
        // Aksi halde XAML'deki {ThemeResource AccentPrimaryBrush} binding'ini
        // geri yükle (ClearValue) — böylece tema değişimi otomatik yansır ve
        // local-set snapshot binding'i kalıcı olarak kırmaz.
        if (AccentBrush is not null)
        {
            IconGlyph.Foreground = AccentBrush;
            ActionTextLabel.Foreground = AccentBrush;
        }
        else
        {
            IconGlyph.ClearValue(FontIcon.ForegroundProperty);
            ActionTextLabel.ClearValue(TextBlock.ForegroundProperty);
        }
    }

    private void ApplyBadge()
    {
        if (BadgeBorder is null || BadgeTextLabel is null)
        {
            return;
        }

        var text = BadgeText;
        if (string.IsNullOrWhiteSpace(text))
        {
            BadgeBorder.Visibility = Visibility.Collapsed;
        }
        else
        {
            BadgeTextLabel.Text = text;
            BadgeBorder.Visibility = Visibility.Visible;
        }
    }

    private void RootButton_Click(object sender, RoutedEventArgs e)
    {
        if (Command is { } cmd && cmd.CanExecute(CommandParameter))
        {
            cmd.Execute(CommandParameter);
        }
    }
}