using System.Windows.Input;
using DefenderUI.Helpers;
using DefenderUI.Models;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace DefenderUI.Controls;

/// <summary>
/// Dashboard hero durum kartı. Severity + metinler + iki komut üzerinden
/// gradient arkaplan ve ikonu otomatik ayarlar.
/// </summary>
public sealed partial class StatusHeroCard : UserControl
{
    // ═════════════════════════════════════════════════════════════════
    // Severity DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty SeverityProperty =
        DependencyProperty.Register(
            nameof(Severity),
            typeof(ProtectionState),
            typeof(StatusHeroCard),
            new PropertyMetadata(ProtectionState.Protected, OnSeverityChanged));

    public ProtectionState Severity
    {
        get => (ProtectionState)GetValue(SeverityProperty);
        set => SetValue(SeverityProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // Title DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty TitleProperty =
        DependencyProperty.Register(
            nameof(Title),
            typeof(string),
            typeof(StatusHeroCard),
            new PropertyMetadata("Bilgisayarınız Korunuyor", OnTitleChanged));

    public string Title
    {
        get => (string)GetValue(TitleProperty);
        set => SetValue(TitleProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // SubTitle DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty SubTitleProperty =
        DependencyProperty.Register(
            nameof(SubTitle),
            typeof(string),
            typeof(StatusHeroCard),
            new PropertyMetadata("Son tarama: bugün 14:30", OnSubTitleChanged));

    public string SubTitle
    {
        get => (string)GetValue(SubTitleProperty);
        set => SetValue(SubTitleProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // PrimaryActionText DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty PrimaryActionTextProperty =
        DependencyProperty.Register(
            nameof(PrimaryActionText),
            typeof(string),
            typeof(StatusHeroCard),
            new PropertyMetadata("Hızlı Tarama", OnPrimaryActionTextChanged));

    public string PrimaryActionText
    {
        get => (string)GetValue(PrimaryActionTextProperty);
        set => SetValue(PrimaryActionTextProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // SecondaryActionText DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty SecondaryActionTextProperty =
        DependencyProperty.Register(
            nameof(SecondaryActionText),
            typeof(string),
            typeof(StatusHeroCard),
            new PropertyMetadata("Tüm Sistemi Tara", OnSecondaryActionTextChanged));

    public string SecondaryActionText
    {
        get => (string)GetValue(SecondaryActionTextProperty);
        set => SetValue(SecondaryActionTextProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // PrimaryActionCommand DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty PrimaryActionCommandProperty =
        DependencyProperty.Register(
            nameof(PrimaryActionCommand),
            typeof(ICommand),
            typeof(StatusHeroCard),
            new PropertyMetadata(null));

    public ICommand? PrimaryActionCommand
    {
        get => (ICommand?)GetValue(PrimaryActionCommandProperty);
        set => SetValue(PrimaryActionCommandProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // SecondaryActionCommand DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty SecondaryActionCommandProperty =
        DependencyProperty.Register(
            nameof(SecondaryActionCommand),
            typeof(ICommand),
            typeof(StatusHeroCard),
            new PropertyMetadata(null));

    public ICommand? SecondaryActionCommand
    {
        get => (ICommand?)GetValue(SecondaryActionCommandProperty);
        set => SetValue(SecondaryActionCommandProperty, value);
    }

    public StatusHeroCard()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        ApplySeverity();
        TitleText.Text = Title;
        SubTitleText.Text = SubTitle;
        PrimaryButton.Content = PrimaryActionText;
        SecondaryButton.Content = SecondaryActionText;
        UpdateShieldPulse();

        // K12: Abonelikleri Loaded'da kur ve çift abonelik korumasıyla ekle.
        MotionPreferences.Changed -= OnMotionPreferencesChanged;
        MotionPreferences.Changed += OnMotionPreferencesChanged;
        this.ActualThemeChanged -= OnActualThemeChanged;
        this.ActualThemeChanged += OnActualThemeChanged;
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        AnimationHelper.StopAnimation(HeroIcon, "Scale");
        MotionPreferences.Changed -= OnMotionPreferencesChanged;
        this.ActualThemeChanged -= OnActualThemeChanged;
    }

    // Faz A #1: Tema değişiminde brush'ları ve gradient alpha'sını yeniden uygula.
    private void OnActualThemeChanged(FrameworkElement sender, object args) => ApplySeverity();

    private void OnMotionPreferencesChanged(object? sender, System.EventArgs e)
    {
        if (DispatcherQueue is null)
        {
            return;
        }
        DispatcherQueue.TryEnqueue(UpdateShieldPulse);
    }

    /// <summary>
    /// Severity "Protected" ise büyük shield ikonuna yumuşak ve yavaş bir
    /// nefes (scale 1.0 → 1.05 → 1.0) animasyonu uygular. Diğer severity'lerde
    /// animasyon durdurulur. <see cref="MotionPreferences.Enabled"/> false ise
    /// çalışmaz.
    /// </summary>
    private void UpdateShieldPulse()
    {
        if (HeroIcon is null)
        {
            return;
        }

        AnimationHelper.StopAnimation(HeroIcon, "Scale");

        if (!MotionPreferences.Enabled)
        {
            return;
        }

        if (Severity == ProtectionState.Protected)
        {
            AnimationHelper.StartPulse(HeroIcon, 1.0f, 1.05f, durationMs: 3000);
        }
    }

    private static void OnSeverityChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is StatusHeroCard card)
        {
            card.ApplySeverity();
            card.UpdateShieldPulse();
        }
    }

    private static void OnTitleChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is StatusHeroCard card && e.NewValue is string s && card.TitleText is not null)
        {
            card.TitleText.Text = s;
        }
    }

    private static void OnSubTitleChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is StatusHeroCard card && e.NewValue is string s && card.SubTitleText is not null)
        {
            card.SubTitleText.Text = s;
        }
    }

    private static void OnPrimaryActionTextChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is StatusHeroCard card && e.NewValue is string s && card.PrimaryButton is not null)
        {
            card.PrimaryButton.Content = s;
        }
    }

    private static void OnSecondaryActionTextChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is StatusHeroCard card && e.NewValue is string s && card.SecondaryButton is not null)
        {
            card.SecondaryButton.Content = s;
        }
    }

    private void ApplySeverity()
    {
        if (HeroIcon is null || IconHalo is null || GradientStop1 is null || GradientStop2 is null)
        {
            return;
        }

        string glyph;
        string fgKey;
        string softKey;
        Color accentColor;

        switch (Severity)
        {
            case ProtectionState.AtRisk:
                glyph = "\uE783"; // ShieldExclamation
                fgKey = "StatusRiskBrush";
                softKey = "StatusRiskSoftBrush";
                accentColor = Color.FromArgb(0xFF, 0xD1, 0x34, 0x38);
                break;
            case ProtectionState.AttentionNeeded:
                glyph = "\uE7BA"; // Warning
                fgKey = "StatusWarningBrush";
                softKey = "StatusWarningSoftBrush";
                accentColor = Color.FromArgb(0xFF, 0xF7, 0xB5, 0x00);
                break;
            case ProtectionState.Scanning:
                glyph = "\uE895"; // Sync
                fgKey = "StatusInfoBrush";
                softKey = "AccentSoftBrush";
                accentColor = Color.FromArgb(0xFF, 0x00, 0x78, 0xD4);
                break;
            case ProtectionState.Protected:
            default:
                glyph = "\uE72E"; // Shield
                fgKey = "StatusProtectedBrush";
                softKey = "StatusProtectedSoftBrush";
                accentColor = Color.FromArgb(0xFF, 0x10, 0x7C, 0x10);
                break;
        }

        HeroIcon.Glyph = glyph;

        if (TryGetBrush(fgKey, out var fgBrush))
        {
            HeroIcon.Foreground = fgBrush;
        }

        if (TryGetBrush(softKey, out var softBrush))
        {
            IconHalo.Fill = softBrush;
        }

        // Faz A #17: Dark temada gradient tonu daha belirgin olmalı (koyu
        // yüzey üzerinde %15 alpha neredeyse görünmezdir).
        var startAlpha = ActualTheme == ElementTheme.Dark ? (byte)0x40 : (byte)0x26;
        GradientStop1.Color = Color.FromArgb(startAlpha, accentColor.R, accentColor.G, accentColor.B);
        GradientStop2.Color = Color.FromArgb(0x00, accentColor.R, accentColor.G, accentColor.B);
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

    private void PrimaryButton_Click(object sender, RoutedEventArgs e)
    {
        if (PrimaryActionCommand is { } cmd && cmd.CanExecute(null))
        {
            cmd.Execute(null);
        }
    }

    private void SecondaryButton_Click(object sender, RoutedEventArgs e)
    {
        if (SecondaryActionCommand is { } cmd && cmd.CanExecute(null))
        {
            cmd.Execute(null);
        }
    }
}