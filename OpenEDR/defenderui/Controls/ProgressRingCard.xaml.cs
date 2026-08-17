using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DefenderUI.Controls;

/// <summary>
/// Tarama ilerleme ringi. Percent, Title, SubTitle ve IsIndeterminate DP'leri
/// ile merkezindeki % metni + alt yazıyı gösterir (Faz 4).
/// </summary>
public sealed partial class ProgressRingCard : UserControl
{
    // ═════════════════════════════════════════════════════════════════
    // Percent DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty PercentProperty =
        DependencyProperty.Register(
            nameof(Percent),
            typeof(double),
            typeof(ProgressRingCard),
            new PropertyMetadata(0.0, OnPercentChanged));

    public double Percent
    {
        get => (double)GetValue(PercentProperty);
        set => SetValue(PercentProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // Title DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty TitleProperty =
        DependencyProperty.Register(
            nameof(Title),
            typeof(string),
            typeof(ProgressRingCard),
            new PropertyMetadata(string.Empty, OnTitleChanged));

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
            typeof(ProgressRingCard),
            new PropertyMetadata(string.Empty, OnSubTitleChanged));

    public string SubTitle
    {
        get => (string)GetValue(SubTitleProperty);
        set => SetValue(SubTitleProperty, value);
    }

    // ═════════════════════════════════════════════════════════════════
    // IsIndeterminate DP
    // ═════════════════════════════════════════════════════════════════
    public static readonly DependencyProperty IsIndeterminateProperty =
        DependencyProperty.Register(
            nameof(IsIndeterminate),
            typeof(bool),
            typeof(ProgressRingCard),
            new PropertyMetadata(false, OnIsIndeterminateChanged));

    public bool IsIndeterminate
    {
        get => (bool)GetValue(IsIndeterminateProperty);
        set => SetValue(IsIndeterminateProperty, value);
    }

    public ProgressRingCard()
    {
        InitializeComponent();
        Loaded += (_, _) =>
        {
            ApplyPercent();
            ApplyTitle();
            ApplySubTitle();
            ApplyIndeterminate();
        };
    }

    private static void OnPercentChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ProgressRingCard c)
        {
            c.ApplyPercent();
        }
    }

    private static void OnTitleChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ProgressRingCard c)
        {
            c.ApplyTitle();
        }
    }

    private static void OnSubTitleChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ProgressRingCard c)
        {
            c.ApplySubTitle();
        }
    }

    private static void OnIsIndeterminateChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ProgressRingCard c)
        {
            c.ApplyIndeterminate();
        }
    }

    private void ApplyPercent()
    {
        if (Ring is null || PercentText is null)
        {
            return;
        }

        var clamped = Percent;
        if (clamped < 0) clamped = 0;
        if (clamped > 100) clamped = 100;

        Ring.Value = clamped;
        PercentText.Text = $"{(int)System.Math.Round(clamped)}%";
    }

    private void ApplyTitle()
    {
        if (TitleText is null)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(Title))
        {
            TitleText.Text = string.Empty;
            TitleText.Visibility = Visibility.Collapsed;
        }
        else
        {
            TitleText.Text = Title;
            TitleText.Visibility = Visibility.Visible;
        }
    }

    private void ApplySubTitle()
    {
        if (SubTitleText is null)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(SubTitle))
        {
            SubTitleText.Text = string.Empty;
            SubTitleText.Visibility = Visibility.Collapsed;
        }
        else
        {
            SubTitleText.Text = SubTitle;
            SubTitleText.Visibility = Visibility.Visible;
        }
    }

    private void ApplyIndeterminate()
    {
        if (Ring is null)
        {
            return;
        }
        Ring.IsIndeterminate = IsIndeterminate;
    }
}