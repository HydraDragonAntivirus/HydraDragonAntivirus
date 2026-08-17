using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DefenderUI.Models;
using DefenderUI.Services;

namespace DefenderUI.ViewModels;

#pragma warning disable MVVMTK0045

/// <summary>
/// Güvenlik duvarı sayfası VM. Ağ profili, uygulama kuralları ve
/// son engellemeleri mock verisiyle besler.
/// </summary>
public partial class FirewallViewModel : ObservableObject
{
    private readonly IToastService? _toastService;
    private readonly IFirewallService? _firewallService;

    // ═══ Hero ═══
    [ObservableProperty]
    private ProtectionState _overallSeverity = ProtectionState.Protected;

    [ObservableProperty]
    private string _heroTitle = "Güvenlik duvarı aktif";

    [ObservableProperty]
    private string _heroSubTitle = "247 gelen, 823 giden kural aktif";

    // ═══ Stats ═══
    [ObservableProperty]
    private string _blockedToday = "127";

    [ObservableProperty]
    private string _activeRules = "1.070";

    [ObservableProperty]
    private string _inboundTraffic = "2.4 GB";

    [ObservableProperty]
    private string _outboundTraffic = "5.8 GB";

    // ═══ Network profile ═══
    [ObservableProperty]
    private string _selectedProfile = "private";

    public bool IsPrivateSelected
    {
        get => SelectedProfile == "private";
        set { if (value) SelectedProfile = "private"; }
    }

    public bool IsPublicSelected
    {
        get => SelectedProfile == "public";
        set { if (value) SelectedProfile = "public"; }
    }

    public bool IsDomainSelected
    {
        get => SelectedProfile == "domain";
        set { if (value) SelectedProfile = "domain"; }
    }

    partial void OnSelectedProfileChanged(string value)
    {
        OnPropertyChanged(nameof(IsPrivateSelected));
        OnPropertyChanged(nameof(IsPublicSelected));
        OnPropertyChanged(nameof(IsDomainSelected));
    }

    // ═══ Application rules ═══
    [ObservableProperty]
    private ObservableCollection<FirewallRuleItem> _applicationRules = new();

    // ═══ Recent blocks ═══
    [ObservableProperty]
    private ObservableCollection<ActivityLogItem> _recentBlocks = new();

    public FirewallViewModel(IToastService? toastService = null, IFirewallService? firewallService = null)
    {
        _toastService = toastService;
        _firewallService = firewallService;
        LoadData();
    }

    private async void LoadData()
    {
        if (_firewallService != null)
        {
            var rules = await _firewallService.GetActiveFirewallRulesAsync();
            ApplicationRules = new ObservableCollection<FirewallRuleItem>(rules);
            ActiveRules = rules.Count.ToString();

            var blockedCount = await _firewallService.GetBlockedCountTodayAsync();
            BlockedToday = blockedCount.ToString();
        }
        else
        {
            ApplicationRules = new ObservableCollection<FirewallRuleItem>
            {
                new() { AppName = "chrome.exe", AppPath = @"C:\Program Files\Google\Chrome\chrome.exe", Action = "İzin Ver", Direction = "Giden", IsEnabled = true, Icon = "\uE774" },
                new() { AppName = "teams.exe", AppPath = @"C:\Users\Default\AppData\Local\Microsoft\Teams\teams.exe", Action = "İzin Ver", Direction = "Gelen/Giden", IsEnabled = true, Icon = "\uE8F2" },
                new() { AppName = "svchost.exe", AppPath = @"C:\Windows\System32\svchost.exe", Action = "Engelle", Direction = "Gelen", IsEnabled = true, Icon = "\uE770" },
                new() { AppName = "outlook.exe", AppPath = @"C:\Program Files\Microsoft Office\root\Office16\outlook.exe", Action = "İzin Ver", Direction = "Giden", IsEnabled = true, Icon = "\uE715" },
                new() { AppName = "spotify.exe", AppPath = @"C:\Users\Default\AppData\Roaming\Spotify\Spotify.exe", Action = "İzin Ver", Direction = "Giden", IsEnabled = false, Icon = "\uE8D6" },
                new() { AppName = "unknown_app.exe", AppPath = @"C:\Users\Default\Downloads\unknown_app.exe", Action = "Engelle", Direction = "Gelen/Giden", IsEnabled = true, Icon = "\uE7BA" },
                new() { AppName = "steam.exe", AppPath = @"C:\Program Files (x86)\Steam\steam.exe", Action = "İzin Ver", Direction = "Gelen/Giden", IsEnabled = true, Icon = "\uE7FC" },
            };
        }

        RecentBlocks = new ObservableCollection<ActivityLogItem>
        {
            new() { Type = ActivityType.ThreatBlocked, Title = "192.168.1.100 adresinden gelen bağlantı engellendi", Timestamp = DateTime.Now.AddMinutes(-5) },
            new() { Type = ActivityType.ThreatBlocked, Title = "Kötü amaçlı IP 45.33.32.156 engellendi", Timestamp = DateTime.Now.AddMinutes(-22) },
            new() { Type = ActivityType.Warning, Title = "unknown_app.exe bağlantı denemesi engellendi", Timestamp = DateTime.Now.AddHours(-1) },
            new() { Type = ActivityType.ThreatBlocked, Title = "Port tarama girişimi (203.0.113.42)", Timestamp = DateTime.Now.AddHours(-3) },
            new() { Type = ActivityType.Warning, Title = "Şüpheli UDP trafiği engellendi", Timestamp = DateTime.Now.AddHours(-6) },
        };
    }

    [RelayCommand]
    private void AddRule() => _toastService?.Info("Kural Ekle", "Bu özellik yakında gelecek.");

    [RelayCommand]
    private void MonitorTraffic() => _toastService?.Info("Trafik Monitörü", "Canlı trafik analizi yakında.");

    [RelayCommand]
    private void EditRule(FirewallRuleItem? rule)
    {
        if (rule is null) return;
        _toastService?.Info(rule.AppName, "Kural düzenleme yakında kullanılabilir olacak.");
    }
}

public partial class FirewallRuleItem : ObservableObject
{
    public string AppName { get; set; } = string.Empty;
    public string AppPath { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string Direction { get; set; } = string.Empty;
    public string Icon { get; set; } = string.Empty;

    [ObservableProperty]
    private bool _isEnabled;

    public bool IsAllow => Action == "İzin Ver";
}

#pragma warning restore MVVMTK0045