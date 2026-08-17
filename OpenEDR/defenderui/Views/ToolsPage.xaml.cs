using DefenderUI.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;

namespace DefenderUI.Views;

/// <summary>
/// Araçlar sayfası. Mock tile'ları <see cref="ToolsViewModel"/> üzerinden gösterir.
/// </summary>
public sealed partial class ToolsPage : Page
{
    public ToolsViewModel ViewModel { get; }

    public ToolsPage()
    {
        ViewModel = App.Current.Services.GetRequiredService<ToolsViewModel>();
        InitializeComponent();
    }
}