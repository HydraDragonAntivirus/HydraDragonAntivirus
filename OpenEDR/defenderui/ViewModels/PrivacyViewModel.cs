using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DefenderUI.Models;
using DefenderUI.Services;

namespace DefenderUI.ViewModels;

#pragma warning disable MVVMTK0045

/// <summary>
/// PrivacyPage'in arka plan modeli. Kamera / mikrofon / izleyici engelleme
/// gibi gizlilik modüllerini ve uygulama izinlerini mock verisiyle yönetir.
/// </summary>
public partial class PrivacyViewModel : ObservableObject
{
    private readonly IToastService? _toastService;
    private readonly INavigationService? _navigationService;

    // ═══ Hero ═══
    [ObservableProperty]
    private ProtectionState _overallSeverity = ProtectionState.Protected;

    [ObservableProperty]
    private string _heroTitle = "Gizliliğiniz korunuyor";

    [ObservableProperty]
    private string _heroSubTitle = "Bugün 47 izleyici engellendi";

    // ═══ Privacy modules ═══
    [ObservableProperty]
    private ObservableCollection<ProtectionModule> _privacyModules = new();

    // ═══ Stats ═══
    [ObservableProperty]
    private string _trackersToday = "47";

    [ObservableProperty]
    private string _trackersWeek = "312";

    [ObservableProperty]
    private string _trackersTotal = "8.4K";

    [ObservableProperty]
    private string _cameraAccessAttempts = "3";

    // ═══ App permissions ═══
    [ObservableProperty]
    private ObservableCollection<AppPermissionItem> _appPermissions = new();

    public PrivacyViewModel(
        IToastService? toastService = null,
        INavigationService? navigationService = null)
    {
        _toastService = toastService;
        _navigationService = navigationService;
        LoadData();
    }

    private void LoadData()
    {
        PrivacyModules = new ObservableCollection<ProtectionModule>
        {
            new() { Name = "Kamera Koruması", Description = "Yetkisiz kamera erişimini engeller", Icon = "\uE960", IsEnabled = true },
            new() { Name = "Mikrofon Koruması", Description = "Yetkisiz mikrofon erişimini engeller", Icon = "\uE720", IsEnabled = true },
            new() { Name = "İzleyici Engelleme", Description = "Web izleyicileri ve çerezleri engeller", Icon = "\uE727", IsEnabled = true },
            new() { Name = "Panoya Koruma", Description = "Hassas pano verilerini korur", Icon = "\uE77F", IsEnabled = false },
            new() { Name = "Ekran Görüntüsü Koruması", Description = "Korunan uygulamalarda ekran görüntüsünü engeller", Icon = "\uE722", IsEnabled = true },
            new() { Name = "Web Kamera Bildirim Işığı", Description = "Erişim olduğunda uyarır", Icon = "\uE8FC", IsEnabled = true },
        };

        AppPermissions = new ObservableCollection<AppPermissionItem>
        {
            new() { AppName = "Google Chrome", AppIcon = "\uE774", PermissionType = "Kamera, Mikrofon", IsAllowed = true },
            new() { AppName = "Zoom", AppIcon = "\uE8AA", PermissionType = "Kamera, Mikrofon", IsAllowed = true },
            new() { AppName = "Skype", AppIcon = "\uE8F2", PermissionType = "Mikrofon", IsAllowed = true },
            new() { AppName = "Slack", AppIcon = "\uE715", PermissionType = "Mikrofon", IsAllowed = false },
        };
    }

    [RelayCommand]
    private void StartPrivacyScan()
    {
        _toastService?.Info("Gizlilik taraması başlatıldı", "İzleyiciler ve izinsiz erişimler kontrol ediliyor…");
    }

    [RelayCommand]
    private void ShowDetails()
    {
        _toastService?.Info("Gizlilik detayları", "Son 7 günün engelleme raporu yakında gelecek.");
    }

    [RelayCommand]
    private void ConfigureModule(ProtectionModule? module)
    {
        if (module is null) return;
        _toastService?.Info(module.Name, "Yapılandırma yakında kullanılabilir olacak.");
    }
}

/// <summary>
/// Gizlilik sayfasındaki uygulama izin satırı için basit mock model.
/// </summary>
public partial class AppPermissionItem : ObservableObject
{
    public string AppName { get; set; } = string.Empty;
    public string AppIcon { get; set; } = string.Empty;
    public string PermissionType { get; set; } = string.Empty;

    [ObservableProperty]
    private bool _isAllowed;
}

#pragma warning restore MVVMTK0045