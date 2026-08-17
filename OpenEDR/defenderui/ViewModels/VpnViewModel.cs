using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DefenderUI.Services;

namespace DefenderUI.ViewModels;

#pragma warning disable MVVMTK0045

/// <summary>
/// VPN tanıtım sayfası için ViewModel. Gerçek bağlantı yok; toggle UI state'i
/// ve sunucu listesini mock olarak yönetir.
/// </summary>
public partial class VpnViewModel : ObservableObject
{
    private readonly IToastService? _toastService;

    // ═══ Connection state ═══
    [ObservableProperty]
    private bool _isConnected;

    [ObservableProperty]
    private string _connectionStatus = "Bağlı Değil";

    [ObservableProperty]
    private string _preferredServer = "İstanbul, Türkiye";

    // ═══ Live stats (visible when connected) ═══
    [ObservableProperty]
    private string _connectionDuration = "00:00:00";

    [ObservableProperty]
    private string _downloaded = "0 MB";

    [ObservableProperty]
    private string _uploaded = "0 MB";

    // ═══ Dashboard stats ═══
    [ObservableProperty]
    private string _activeDurationStat = "0 dk";

    [ObservableProperty]
    private string _monthlyUsage = "4.8 GB / 10 GB";

    [ObservableProperty]
    private string _connectedServer = "Bağlı Değil";

    // ═══ Server list ═══
    [ObservableProperty]
    private ObservableCollection<VpnServerItem> _servers = new();

    // ═══ Feature toggles ═══
    [ObservableProperty]
    private bool _killSwitchEnabled = true;

    [ObservableProperty]
    private bool _splitTunnelingEnabled;

    [ObservableProperty]
    private bool _autoConnectEnabled = true;

    public string ToggleButtonText => IsConnected ? "Bağlantıyı Kes" : "Bağlan";

    partial void OnIsConnectedChanged(bool value)
    {
        OnPropertyChanged(nameof(ToggleButtonText));
    }

    public VpnViewModel(IToastService? toastService = null)
    {
        _toastService = toastService;
        LoadServers();
    }

    private void LoadServers()
    {
        Servers = new ObservableCollection<VpnServerItem>
        {
            new("🇹🇷", "Türkiye", "İstanbul", 12, PingQuality.Good),
            new("🇩🇪", "Almanya", "Berlin", 45, PingQuality.Good),
            new("🇳🇱", "Hollanda", "Amsterdam", 38, PingQuality.Good),
            new("🇬🇧", "Birleşik Krallık", "Londra", 58, PingQuality.Medium),
            new("🇺🇸", "ABD", "New York", 98, PingQuality.Medium),
            new("🇺🇸", "ABD", "Los Angeles", 145, PingQuality.Medium),
            new("🇨🇦", "Kanada", "Toronto", 110, PingQuality.Medium),
            new("🇯🇵", "Japonya", "Tokyo", 180, PingQuality.Slow),
            new("🇸🇬", "Singapur", "Singapur", 195, PingQuality.Slow),
            new("🇦🇺", "Avustralya", "Sidney", 240, PingQuality.Slow),
        };
    }

    [RelayCommand]
    private void ToggleConnection()
    {
        IsConnected = !IsConnected;
        if (IsConnected)
        {
            ConnectionStatus = "Bağlı";
            ConnectionDuration = "00:23:14";
            Downloaded = "1.2 GB";
            Uploaded = "340 MB";
            ActiveDurationStat = "23 dk";
            ConnectedServer = "İstanbul";
            _toastService?.Success("VPN Bağlandı", $"Sunucu: {PreferredServer}");
        }
        else
        {
            ConnectionStatus = "Bağlı Değil";
            ConnectionDuration = "00:00:00";
            Downloaded = "0 MB";
            Uploaded = "0 MB";
            ActiveDurationStat = "0 dk";
            ConnectedServer = "Bağlı Değil";
            _toastService?.Info("VPN Bağlantısı Kesildi", null);
        }
    }

    [RelayCommand]
    private void ChangeServer()
    {
        _toastService?.Info("Sunucu Değiştir", "Aşağıdaki listeden tercih ettiğiniz sunucuyu seçebilirsiniz.");
    }

    [RelayCommand]
    private void ConnectToServer(VpnServerItem? server)
    {
        if (server is null) return;
        PreferredServer = $"{server.City}, {server.Country}";
        ConnectedServer = server.City;
        if (!IsConnected)
        {
            ToggleConnection();
        }
        else
        {
            _toastService?.Success("Sunucu değiştirildi", $"{server.City}, {server.Country}");
        }
    }

    [RelayCommand]
    private void UpgradeToPremium()
    {
        _toastService?.Info("Sınırsız VPN", "Premium plan satın alma akışı yakında.");
    }
}

/// <summary>
/// Bayrak / ülke / şehir / ping bilgisini barındıran mock sunucu kaydı.
/// </summary>
public record VpnServerItem(string Flag, string Country, string City, int PingMs, PingQuality Quality)
{
    public string PingText => $"{PingMs} ms";
}

/// <summary>
/// Ping seviyesi — UI rozet renklendirmesi için.
/// </summary>
public enum PingQuality
{
    Good,
    Medium,
    Slow
}

#pragma warning restore MVVMTK0045