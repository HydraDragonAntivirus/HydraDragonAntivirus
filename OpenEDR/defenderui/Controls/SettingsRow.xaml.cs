using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Markup;

namespace DefenderUI.Controls;

/// <summary>
/// Settings sayfasında kullanılan standart satır kontrolü.
/// İçerik (ToggleSwitch, ComboBox, Button vb.) dış XAML'de doğrudan
/// &lt;local:SettingsRow&gt;...&lt;/local:SettingsRow&gt; syntax'ı ile verilebilsin diye
/// <see cref="ContentPropertyAttribute"/> ile <see cref="RowContent"/> işaretlenmiştir.
/// </summary>
[ContentProperty(Name = nameof(RowContent))]
public sealed partial class SettingsRow : UserControl
{
    // ═══════════════════════════════════════════════════════
    // Title
    // ═══════════════════════════════════════════════════════
    public static readonly DependencyProperty TitleProperty =
        DependencyProperty.Register(
            nameof(Title),
            typeof(string),
            typeof(SettingsRow),
            new PropertyMetadata(string.Empty, OnTitleChanged));

    public string Title
    {
        get => (string)GetValue(TitleProperty);
        set => SetValue(TitleProperty, value);
    }

    private static void OnTitleChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is SettingsRow row && e.NewValue is string s && row.TitleLabel is not null)
        {
            row.TitleLabel.Text = s;
        }
    }

    // ═══════════════════════════════════════════════════════
    // Description
    // ═══════════════════════════════════════════════════════
    public static readonly DependencyProperty DescriptionProperty =
        DependencyProperty.Register(
            nameof(Description),
            typeof(string),
            typeof(SettingsRow),
            new PropertyMetadata(string.Empty, OnDescriptionChanged));

    public string Description
    {
        get => (string)GetValue(DescriptionProperty);
        set => SetValue(DescriptionProperty, value);
    }

    private static void OnDescriptionChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is SettingsRow row && row.DescriptionLabel is not null)
        {
            var text = e.NewValue as string ?? string.Empty;
            row.DescriptionLabel.Text = text;
            row.DescriptionLabel.Visibility =
                string.IsNullOrWhiteSpace(text) ? Visibility.Collapsed : Visibility.Visible;
        }
    }

    // ═══════════════════════════════════════════════════════
    // Glyph (opsiyonel)
    // ═══════════════════════════════════════════════════════
    public static readonly DependencyProperty GlyphProperty =
        DependencyProperty.Register(
            nameof(Glyph),
            typeof(string),
            typeof(SettingsRow),
            new PropertyMetadata(string.Empty, OnGlyphChanged));

    public string Glyph
    {
        get => (string)GetValue(GlyphProperty);
        set => SetValue(GlyphProperty, value);
    }

    private static void OnGlyphChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is SettingsRow row && row.IconGlyph is not null)
        {
            var g = e.NewValue as string ?? string.Empty;
            row.IconGlyph.Glyph = g;
            row.IconGlyph.Visibility =
                string.IsNullOrWhiteSpace(g) ? Visibility.Collapsed : Visibility.Visible;
        }
    }

    // ═══════════════════════════════════════════════════════
    // RowContent — XAML content property
    // ═══════════════════════════════════════════════════════
    public static readonly DependencyProperty RowContentProperty =
        DependencyProperty.Register(
            nameof(RowContent),
            typeof(object),
            typeof(SettingsRow),
            new PropertyMetadata(null));

    public object? RowContent
    {
        get => GetValue(RowContentProperty);
        set => SetValue(RowContentProperty, value);
    }

    public SettingsRow()
    {
        InitializeComponent();
        Loaded += (_, _) =>
        {
            TitleLabel.Text = Title;
            DescriptionLabel.Text = Description;
            DescriptionLabel.Visibility =
                string.IsNullOrWhiteSpace(Description) ? Visibility.Collapsed : Visibility.Visible;
            IconGlyph.Glyph = Glyph;
            IconGlyph.Visibility =
                string.IsNullOrWhiteSpace(Glyph) ? Visibility.Collapsed : Visibility.Visible;
        };
    }
}