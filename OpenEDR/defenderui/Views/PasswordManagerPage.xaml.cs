using DefenderUI.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;

namespace DefenderUI.Views;

/// <summary>
/// Parola Yöneticisi tanıtım sayfası. Feature gerçek değil; CTA'lar toast gösterir.
/// </summary>
public sealed partial class PasswordManagerPage : Page
{
    public PasswordManagerViewModel ViewModel { get; }

    public PasswordManagerPage()
    {
        ViewModel = App.Current.Services.GetRequiredService<PasswordManagerViewModel>();
        InitializeComponent();
    }
}