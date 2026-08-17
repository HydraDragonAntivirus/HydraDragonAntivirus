using System.Windows.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace DefenderUI.Controls;

/// <summary>
/// Modül durumları — yeşil "Aktif", gri "Kapalı", sarı "Dikkat" gibi.
/// </summary>
public enum ProtectionModuleStatus
{
    On,
    Off,
    Warning
}

/// <summary>
/// Tek bir koruma modülü kartı. İkon + başlık + açıklama + toggle + "Yapılandır" link.
/// </summary>
public sealed partial class ProtectionModuleCard : UserControl
{
    // ═══════════════════════════════════════════════════════
    // Glyph
    // ═══════════════════════════════════════════════════════
    public static readonly DependencyProperty GlyphProperty =
        DependencyProperty.Register(
            nameof(Glyph),
            typeof(string),
            typeof(ProtectionModuleCard),
            new PropertyMetadata("\uE72E", OnGlyphChanged));

    public string Glyph
    {
        get => (string)GetValue(GlyphProperty);
        set => SetValue(GlyphProperty, value);
    }

    private static void OnGlyphChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ProtectionModuleCard card && e.NewValue is string s && card.IconGlyph is not null)
        {
            card.IconGlyph.Glyph = s;
        }
    }

    // ═══════════════════════════════════════════════════════
    // Title
    // ═══════════════════════════════════════════════════════
    public static readonly DependencyProperty TitleProperty =
        DependencyProperty.Register(
            nameof(Title),
            typeof(string),
            typeof(ProtectionModuleCard),
            new PropertyMetadata("Modül", OnTitleChanged));

    public string Title
    {
        get => (string)GetValue(TitleProperty);
        set => SetValue(TitleProperty, value);
    }

    private static void OnTitleChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ProtectionModuleCard card && e.NewValue is string s && card.TitleLabel is not null)
        {
            card.TitleLabel.Text = s;
        }
    }

    // ═══════════════════════════════════════════════════════
    // Description
    // ═══════════════════════════════════════════════════════
    public static readonly DependencyProperty DescriptionProperty =
        DependencyProperty.Register(
            nameof(Description),
            typeof(string),
            typeof(ProtectionModuleCard),
            new PropertyMetadata(string.Empty, OnDescriptionChanged));

    public string Description
    {
        get => (string)GetValue(DescriptionProperty);
        set => SetValue(DescriptionProperty, value);
    }

    private static void OnDescriptionChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ProtectionModuleCard card && e.NewValue is string s && card.DescriptionLabel is not null)
        {
            card.DescriptionLabel.Text = s;
        }
    }

    // ═══════════════════════════════════════════════════════
    // IsModuleEnabled (two-way) - ToggleSwitch.IsOn'a bağlı
    // "IsEnabled" adı UIElement ile çakışır, bu yüzden IsModuleEnabled.
    // ═══════════════════════════════════════════════════════
    public static readonly DependencyProperty IsModuleEnabledProperty =
        DependencyProperty.Register(
            nameof(IsModuleEnabled),
            typeof(bool),
            typeof(ProtectionModuleCard),
            new PropertyMetadata(true, OnIsModuleEnabledChanged));

    public bool IsModuleEnabled
    {
        get => (bool)GetValue(IsModuleEnabledProperty);
        set => SetValue(IsModuleEnabledProperty, value);
    }

    private static void OnIsModuleEnabledChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ProtectionModuleCard card && card.ModuleToggle is not null && e.NewValue is bool b)
        {
            if (card.ModuleToggle.IsOn != b)
            {
                card.ModuleToggle.IsOn = b;
            }

            // Status'u otomatik güncelle
            card.Status = b ? ProtectionModuleStatus.On : ProtectionModuleStatus.Off;
        }
    }

    // ═══════════════════════════════════════════════════════
    // Status
    // ═══════════════════════════════════════════════════════
    public static readonly DependencyProperty StatusProperty =
        DependencyProperty.Register(
            nameof(Status),
            typeof(ProtectionModuleStatus),
            typeof(ProtectionModuleCard),
            new PropertyMetadata(ProtectionModuleStatus.On, OnStatusChanged));

    public ProtectionModuleStatus Status
    {
        get => (ProtectionModuleStatus)GetValue(StatusProperty);
        set => SetValue(StatusProperty, value);
    }

    private static void OnStatusChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ProtectionModuleCard card)
        {
            card.ApplyStatus();
        }
    }

    // ═══════════════════════════════════════════════════════
    // ConfigureCommand
    // ═══════════════════════════════════════════════════════
    public static readonly DependencyProperty ConfigureCommandProperty =
        DependencyProperty.Register(
            nameof(ConfigureCommand),
            typeof(ICommand),
            typeof(ProtectionModuleCard),
            new PropertyMetadata(null));

    public ICommand? ConfigureCommand
    {
        get => (ICommand?)GetValue(ConfigureCommandProperty);
        set => SetValue(ConfigureCommandProperty, value);
    }

    public static readonly DependencyProperty ConfigureCommandParameterProperty =
        DependencyProperty.Register(
            nameof(ConfigureCommandParameter),
            typeof(object),
            typeof(ProtectionModuleCard),
            new PropertyMetadata(null));

    public object? ConfigureCommandParameter
    {
        get => GetValue(ConfigureCommandParameterProperty);
        set => SetValue(ConfigureCommandParameterProperty, value);
    }

    public ProtectionModuleCard()
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
        ModuleToggle.IsOn = IsModuleEnabled;
        ApplyStatus();

        // K12: Çift abonelik korumasıyla tema değişim handler'ını bağla.
        this.ActualThemeChanged -= OnActualThemeChanged;
        this.ActualThemeChanged += OnActualThemeChanged;
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        this.ActualThemeChanged -= OnActualThemeChanged;
    }

    // Faz A #2: Tema değişince status dot + "Aktif/Kapalı" rengini yeniden uygula.
    private void OnActualThemeChanged(FrameworkElement sender, object args) => ApplyStatus();

    private void ApplyStatus()
    {
        if (StatusDot is null || StatusLabel is null)
        {
            return;
        }

        string text;
        string brushKey;

        switch (Status)
        {
            case ProtectionModuleStatus.Off:
                text = "Kapalı";
                brushKey = "TextTertiaryBrush";
                break;
            case ProtectionModuleStatus.Warning:
                text = "Dikkat";
                brushKey = "StatusWarningBrush";
                break;
            case ProtectionModuleStatus.On:
            default:
                text = "Aktif";
                brushKey = "StatusProtectedBrush";
                break;
        }

        StatusLabel.Text = text;

        if (TryGetBrush(brushKey, out var brush))
        {
            StatusDot.Fill = brush;
            StatusLabel.Foreground = brush;
        }
    }

    private bool TryGetBrush(string key, out Brush brush)
    {
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

    private void ModuleToggle_Toggled(object sender, RoutedEventArgs e)
    {
        if (ModuleToggle is null)
        {
            return;
        }

        if (IsModuleEnabled != ModuleToggle.IsOn)
        {
            IsModuleEnabled = ModuleToggle.IsOn;
        }
    }

    private void ConfigureLink_Click(object sender, RoutedEventArgs e)
    {
        if (ConfigureCommand is { } cmd && cmd.CanExecute(ConfigureCommandParameter))
        {
            cmd.Execute(ConfigureCommandParameter);
        }
    }
}