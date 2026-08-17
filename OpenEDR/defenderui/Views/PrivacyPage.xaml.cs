using DefenderUI.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;

namespace DefenderUI.Views;

/// <summary>
/// Gizlilik koruması sayfası. MVVM için DI üzerinden <see cref="PrivacyViewModel"/>
/// enjekte edilir; code-behind mantıktan uzak tutulur.
/// </summary>
public sealed partial class PrivacyPage : Page
{
    public PrivacyViewModel ViewModel { get; }

    public PrivacyPage()
    {
        ViewModel = App.Current.Services.GetRequiredService<PrivacyViewModel>();
        InitializeComponent();
    }
}