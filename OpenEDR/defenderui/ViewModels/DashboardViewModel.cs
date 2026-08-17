using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DefenderUI.Models;
using DefenderUI.Services;

namespace DefenderUI.ViewModels;

#pragma warning disable MVVMTK0045 // Using [ObservableProperty] with fields for WinRT compatibility

public partial class DashboardViewModel : ObservableObject
{
    private readonly MockDataService _mockDataService;
    private readonly INavigationService? _navigationService;

    // ═════════════════════════════════════════════════════════════════
    // Hero (Faz 3)
    // ═════════════════════════════════════════════════════════════════
    [ObservableProperty]
    private ProtectionState _overallStatus;

    [ObservableProperty]
    private string _heroTitle = "Bilgisayarınız Korunuyor";

    [ObservableProperty]
    private string _heroSubTitle = string.Empty;

    // ═════════════════════════════════════════════════════════════════
    // Stat Cards (Faz 3)
    // ═════════════════════════════════════════════════════════════════
    [ObservableProperty]
    private string _filesScanned = "0";

    [ObservableProperty]
    private int _filesScannedValue;

    [ObservableProperty]
    private int _threatsBlocked;

    [ObservableProperty]
    private int _quarantinedCount;

    [ObservableProperty]
    private string _lastScanRelative = string.Empty;

    // ═════════════════════════════════════════════════════════════════
    // Feature tiles (Faz 3)
    // ═════════════════════════════════════════════════════════════════
    [ObservableProperty]
    private ObservableCollection<FeatureTileData> _featureTiles = new();

    // ═════════════════════════════════════════════════════════════════
    // Legacy properties (geriye dönük uyumluluk - mevcut bindings için)
    // ═════════════════════════════════════════════════════════════════
    [ObservableProperty]
    private ProtectionState _protectionState;

    [ObservableProperty]
    private int _securityScore;

    [ObservableProperty]
    private string _statusMessage = string.Empty;

    [ObservableProperty]
    private string _statusDescription = string.Empty;

    [ObservableProperty]
    private int _threatsDetected;

    [ObservableProperty]
    private int _quarantinedItems;

    [ObservableProperty]
    private int _blockedAttacks;

    [ObservableProperty]
    private int _protectedFiles;

    [ObservableProperty]
    private int _suspiciousActivity;

    [ObservableProperty]
    private string _lastScanDate = string.Empty;

    [ObservableProperty]
    private string _lastScanDuration = string.Empty;

    [ObservableProperty]
    private int _lastScanFilesChecked;

    [ObservableProperty]
    private int _lastScanThreatsFound;

    // Protection Modules
    [ObservableProperty]
    private ObservableCollection<ProtectionModule> _protectionModules = new();

    // Activity Log
    [ObservableProperty]
    private ObservableCollection<ActivityLogItem> _recentActivities = new();

    // Update Info
    [ObservableProperty]
    private string _virusDefinitionVersion = string.Empty;

    [ObservableProperty]
    private string _appVersion = string.Empty;

    [ObservableProperty]
    private string _lastUpdateDate = string.Empty;

    [ObservableProperty]
    private bool _isUpdateAvailable;

    // System Health
    [ObservableProperty]
    private int _healthScore;

    [ObservableProperty]
    private double _cpuImpact;

    [ObservableProperty]
    private double _memoryUsage;

    [ObservableProperty]
    private bool _autoUpdatesEnabled;

    [ObservableProperty]
    private bool _backgroundProtection;

    [ObservableProperty]
    private ObservableCollection<string> _alerts = new();

    private readonly IWindowsDefenderService? _defenderService;
    private readonly ISettingsService? _settingsService;

    // ═════════════════════════════════════════════════════════════════
    // Ctor (INavigationService opsiyonel — Test/Designer için)
    // ═════════════════════════════════════════════════════════════════
    public DashboardViewModel(
        MockDataService mockDataService,
        INavigationService? navigationService = null,
        IWindowsDefenderService? defenderService = null,
        ISettingsService? settingsService = null)
    {
        _mockDataService = mockDataService;
        _navigationService = navigationService;
        _defenderService = defenderService;
        _settingsService = settingsService;
        LoadData();
    }

    private async void LoadData()
    {
        if (_settingsService?.CurrentSettings.UseRealDefenderEngine == true && _defenderService != null)
        {
            var liveStatus = await _defenderService.GetLiveProtectionStatusAsync();
            ProtectionState = liveStatus.State;
            OverallStatus = ComputeOverallStatus(liveStatus.State);
            SecurityScore = liveStatus.SecurityScore;
            StatusMessage = liveStatus.StatusMessage;
            StatusDescription = liveStatus.Description;
            HeroTitle = liveStatus.StatusMessage;
            HeroSubTitle = liveStatus.Description;

            var version = await _defenderService.GetAntivirusSignatureVersionAsync();
            VirusDefinitionVersion = version;
        }
        else
        {
            var status = _mockDataService.GetProtectionStatus();
            ProtectionState = status.State;
            OverallStatus = ComputeOverallStatus(status.State);
            SecurityScore = status.SecurityScore;
            StatusMessage = status.StatusMessage;
            StatusDescription = status.Description;
        }

        var threats = _mockDataService.GetRecentThreats();
        ThreatsDetected = threats.Count;
        QuarantinedItems = threats.Count(t => t.IsQuarantined);
        BlockedAttacks = threats.Count(t => t.ActionTaken == "Blocked");
        SuspiciousActivity = threats.Count(t => t.RiskLevel == RiskLevel.Medium);

        ProtectedFiles = 128_457;

        // Faz 3 — Stat Cards
        FilesScannedValue = 12_345;
        FilesScanned = FilesScannedValue.ToString("N0");
        ThreatsBlocked = BlockedAttacks;
        QuarantinedCount = QuarantinedItems;

        // Protection Modules
        ProtectionModules = new ObservableCollection<ProtectionModule>(_mockDataService.GetProtectionModules());

        // Recent Activities
        RecentActivities = new ObservableCollection<ActivityLogItem>(_mockDataService.GetRecentActivity());

        // Feature Tiles (Faz 3)
        FeatureTiles = new ObservableCollection<FeatureTileData>(_mockDataService.GetFeatureTiles());

        // Update Info
        var updateInfo = _mockDataService.GetUpdateInfo();
        VirusDefinitionVersion = updateInfo.VirusDefinitionVersion;
        AppVersion = updateInfo.AppVersion;
        LastUpdateDate = updateInfo.LastUpdateDate.ToString("dd MMM yyyy HH:mm");
        IsUpdateAvailable = updateInfo.IsUpdateAvailable;

        // System Health
        var healthInfo = _mockDataService.GetSystemHealthInfo();
        HealthScore = healthInfo.HealthScore;
        CpuImpact = healthInfo.CpuImpact;
        MemoryUsage = healthInfo.MemoryUsage;
        AutoUpdatesEnabled = healthInfo.AutoUpdates;
        BackgroundProtection = healthInfo.BackgroundProtection;

        // Alerts
        Alerts = new ObservableCollection<string>
        {
            "Zamanlanmış tarama gecikti — son tarama 3 gün önce",
            "Karantinada incelenmesi gereken 2 öğe var"
        };

        var lastScan = _mockDataService.GetLastScanResult();
        LastScanDate = lastScan.StartTime.ToString("dd MMM yyyy HH:mm");
        LastScanDuration = $"{lastScan.Duration.Minutes}dk {lastScan.Duration.Seconds}sn";
        LastScanFilesChecked = lastScan.FilesScanned;
        LastScanThreatsFound = lastScan.ThreatsFound;

        LastScanRelative = BuildRelativeTime(lastScan.StartTime);
        HeroSubTitle = $"Son tarama: {LastScanRelative}";
        HeroTitle = OverallStatus switch
        {
            ProtectionState.AtRisk => "Dikkat! Sisteminizde Risk Var",
            ProtectionState.AttentionNeeded => "İlgilenilmesi Gereken Öğeler Var",
            ProtectionState.Scanning => "Sistem Taranıyor",
            _ => "Bilgisayarınız Korunuyor"
        };
    }

    private ProtectionState ComputeOverallStatus(ProtectionState baseState)
    {
        // Basit kural: karantinada çözülmemiş Critical tehdit → Risk;
        // son 24 saatte engellenen tehdit → AttentionNeeded; aksi → Protected.
        var threats = _mockDataService.GetRecentThreats();
        var now = DateTime.Now;

        var criticalQuarantined = threats.Any(t =>
            t.IsQuarantined && t.RiskLevel == RiskLevel.Critical);
        if (criticalQuarantined)
        {
            return ProtectionState.AtRisk;
        }

        var recentThreat = threats.Any(t => (now - t.DetectionDate).TotalHours <= 24);
        if (recentThreat)
        {
            return ProtectionState.AttentionNeeded;
        }

        return baseState;
    }

    private static string BuildRelativeTime(DateTime time)
    {
        var delta = DateTime.Now - time;
        if (delta.TotalMinutes < 1)
        {
            return "az önce";
        }
        if (delta.TotalMinutes < 60)
        {
            return $"{(int)delta.TotalMinutes} dakika önce";
        }
        if (delta.TotalHours < 24)
        {
            return $"{(int)delta.TotalHours} saat önce";
        }
        if (delta.TotalDays < 7)
        {
            return $"{(int)delta.TotalDays} gün önce";
        }
        return time.ToString("dd MMM yyyy");
    }

    // ═════════════════════════════════════════════════════════════════
    // Commands (Faz 3)
    // ═════════════════════════════════════════════════════════════════
    [RelayCommand]
    private void QuickScan() => _navigationService?.NavigateTo("scan", "quick");

    [RelayCommand]
    private void FullScan() => _navigationService?.NavigateTo("scan", "full");

    [RelayCommand]
    private void CustomScan() => _navigationService?.NavigateTo("scan", "custom");

    [RelayCommand]
    private void UpdateNow() => _navigationService?.NavigateTo("update");

    [RelayCommand]
    private void UpdateDatabase() => _navigationService?.NavigateTo("update");

    [RelayCommand]
    private void OpenQuarantine() => _navigationService?.NavigateTo("quarantine");

    [RelayCommand]
    private void OpenReports() => _navigationService?.NavigateTo("reports");

    [RelayCommand]
    private void OpenPrivacy() => _navigationService?.NavigateTo("protection");

    [RelayCommand]
    private void ViewAllActivities() => _navigationService?.NavigateTo("reports");

    [RelayCommand]
    private void FeatureTile(string? navigateKey)
    {
        if (string.IsNullOrWhiteSpace(navigateKey))
        {
            return;
        }
        _navigationService?.NavigateTo(navigateKey);
    }

    // ═════════════════════════════════════════════════════════════════
    // Legacy Commands (Faz 2/erken Faz 3 — mevcut bindingler için korunuyor)
    // ═════════════════════════════════════════════════════════════════
    [RelayCommand]
    private void FixIssues()
    {
        // UI placeholder
    }

    [RelayCommand]
    private void CheckForUpdates() => _navigationService?.NavigateTo("update");

    [RelayCommand]
    private void ViewAllActivity() => _navigationService?.NavigateTo("reports");

    [RelayCommand]
    private void RunScanNow() => _navigationService?.NavigateTo("scan", "quick");

    [RelayCommand]
    private void ViewQuarantine() => _navigationService?.NavigateTo("quarantine");
}

#pragma warning restore MVVMTK0045