using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;
using DefenderUI.Controls;
using DefenderUI.Helpers;
using DefenderUI.Services;
using DefenderUI.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace DefenderUI.Views;

/// <summary>
/// Scan sayfası (Faz 4). IScanService + ScanViewModel ile çalışır;
/// ItemsRepeater içindeki ScanModeCard'ların IsSelected durumunu
/// ViewModel.SelectedMode değişikliklerine göre code-behind'da yönetir.
/// </summary>
public sealed partial class ScanPage : Page
{
    public ScanViewModel ViewModel { get; }

    public ScanPage()
    {
        ViewModel = App.Current.Services.GetRequiredService<ScanViewModel>();
        InitializeComponent();
        DataContext = ViewModel;

        ViewModel.PropertyChanged += OnViewModelPropertyChanged;
        Unloaded += OnUnloaded;
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        // Sayfa kaldırılınca event aboneliklerini sök — leak önlemi.
        ViewModel.PropertyChanged -= OnViewModelPropertyChanged;
        Unloaded -= OnUnloaded;
    }

    private void Page_Loaded(object sender, RoutedEventArgs e)
    {
        // Faz 7: Sayfa yüklendiğinde root content için yumuşak fade+slide.
        if (RootContent is not null)
        {
            AnimationHelper.FadeInSlide(RootContent, durationMs: 280, offsetY: 16f);
        }
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        ViewModel.ApplyNavigationParameter(e.Parameter);
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ViewModel.SelectedMode))
        {
            UpdateModeCardSelection();
        }
    }

    private void UpdateModeCardSelection()
    {
        var root = IdleStatePanel;
        if (root is null) return;

        foreach (var card in EnumerateScanModeCards(root))
        {
            card.IsSelected = card.Mode == ViewModel.SelectedMode;
        }
    }

    private static System.Collections.Generic.IEnumerable<ScanModeCard> EnumerateScanModeCards(DependencyObject parent)
    {
        var count = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetChildrenCount(parent);
        for (int i = 0; i < count; i++)
        {
            var child = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetChild(parent, i);
            if (child is ScanModeCard card)
            {
                yield return card;
            }
            foreach (var sub in EnumerateScanModeCards(child))
            {
                yield return sub;
            }
        }
    }

    private void AddPathButton_Click(object sender, RoutedEventArgs e)
    {
        // Not: FolderPicker host Window gerektirir; basitleştirmek adına
        // MVP'de örnek bir path ekleyelim. İleri fazda FolderPicker entegre edilecek.
        // K8: Gerçek bir await yok — gereksiz async void kaldırıldı.
        var samples = new[]
        {
            @"C:\Users",
            @"C:\Program Files",
            @"C:\Windows\System32",
            @"D:\Documents",
            @"D:\Downloads",
            @"E:\"
        };

        var existing = ViewModel.CustomPaths.ToHashSet();
        var candidate = samples.FirstOrDefault(s => !existing.Contains(s));
        if (candidate is not null)
        {
            ViewModel.AddCustomPathCommand.Execute(candidate);
        }
    }

    /// <summary>
    /// x:Bind fonksiyon çağrısı — CustomPaths boşsa Visible, değilse Collapsed.
    /// </summary>
    public static Visibility IsCollectionEmpty(int count)
        => count == 0 ? Visibility.Visible : Visibility.Collapsed;
}