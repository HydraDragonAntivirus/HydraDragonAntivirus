using DefenderUI.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DefenderUI.Views;

public sealed partial class SettingsPage : Page
{
    public SettingsViewModel ViewModel { get; }

    public SettingsPage()
    {
        ViewModel = App.Current.Services.GetRequiredService<SettingsViewModel>();
        InitializeComponent();
    }

    private void Page_Loaded(object sender, RoutedEventArgs e)
    {
        // Sade; kart stilleri hover'ı zaten sağlıyor.
    }

    // ═════════════════════════════════════════════════════════════════
    // Static helpers — x:Bind visibility kararları.
    // ═════════════════════════════════════════════════════════════════

    public static Visibility IsCategory(SettingsCategory? category, string key)
    {
        return category?.Key == key ? Visibility.Visible : Visibility.Collapsed;
    }

    public static Visibility IsPlaceholder(SettingsCategory? category)
    {
        if (category is null) return Visibility.Collapsed;
        // general ve appearance gerçek içerikli
        return category.Key is "general" or "appearance"
            ? Visibility.Collapsed
            : Visibility.Visible;
    }

    public static string GetCategoryTitle(SettingsCategory? category)
        => category?.Title ?? string.Empty;
}