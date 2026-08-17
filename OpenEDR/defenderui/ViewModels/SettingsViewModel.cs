using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DefenderUI.Helpers;
using DefenderUI.Services;
using Microsoft.UI.Xaml;

namespace DefenderUI.ViewModels;

public record SettingsCategory(string Key, string Title, string Glyph);

public partial class SettingsViewModel : ObservableObject
{
    private readonly MockDataService _mockDataService;
    private readonly IThemeService _themeService;
    private readonly ISettingsService? _settingsService;
    private readonly ILocalizationService? _localizationService;

    [ObservableProperty] private ObservableCollection<SettingsCategory> _categories = [];
    [ObservableProperty] private SettingsCategory? _selectedCategory;

    // General
    [ObservableProperty] private bool _startWithWindows = true;
    [ObservableProperty] private bool _minimizeToTray = true;
    [ObservableProperty] private bool _showNotifications = true;
    [ObservableProperty] private string _selectedLanguage = "Türkçe";
    [ObservableProperty] private bool _telemetryEnabled;
    [ObservableProperty] private bool _useRealDefenderEngine;

    // Appearance / Theme
    [ObservableProperty] private ElementTheme _selectedElementTheme = ElementTheme.Default;
    [ObservableProperty] private bool _isLightThemeSelected;
    [ObservableProperty] private bool _isDarkThemeSelected;
    [ObservableProperty] private bool _isSystemThemeSelected = true;
    [ObservableProperty] private bool _compactMode;
    [ObservableProperty] private bool _reduceMotion;

    // Protection
    [ObservableProperty] private bool _realTimeProtection = true;
    [ObservableProperty] private bool _cloudProtection = true;
    [ObservableProperty] private bool _automaticSampleSubmission;
    [ObservableProperty] private string _scanSensitivity = "Balanced";
    [ObservableProperty] private bool _scanArchives = true;
    [ObservableProperty] private bool _scanRemovableDrives = true;
    [ObservableProperty] private bool _scanNetworkDrives;

    // Notifications
    [ObservableProperty] private bool _threatNotifications = true;
    [ObservableProperty] private bool _scanCompleteNotifications = true;
    [ObservableProperty] private bool _updateNotifications = true;
    [ObservableProperty] private bool _weeklyReportNotifications;
    [ObservableProperty] private bool _soundAlerts;

    // Scheduled Scans
    [ObservableProperty] private bool _scheduledScanEnabled = true;
    [ObservableProperty] private string _scanFrequency = "Weekly";
    [ObservableProperty] private string _scanDay = "Monday";
    [ObservableProperty] private string _scanTime = "02:00 AM";
    [ObservableProperty] private string _scheduledScanType = "Quick Scan";

    // Exclusions
    [ObservableProperty] private ObservableCollection<string> _excludedFiles = [];
    [ObservableProperty] private ObservableCollection<string> _excludedFolders = [];

    // Legacy / Privacy / About
    [ObservableProperty] private string _selectedTheme = "System";
    [ObservableProperty] private string _accentColor = "Blue";
    [ObservableProperty] private bool _sendUsageData;
    [ObservableProperty] private bool _sendCrashReports = true;
    [ObservableProperty] private bool _participateInBeta;
    [ObservableProperty] private string _appVersionInfo = "HydraDragonAntivirus v1.2.0";
    [ObservableProperty] private string _buildNumber = "Build 2026.04.17.001";
    [ObservableProperty] private string _licenseType = "Premium License";
    [ObservableProperty] private string _licenseExpiry = "Dec 31, 2027";

    // ComboBox item sources
    public List<string> Languages { get; } = ["Türkçe", "English", "Deutsch", "Français", "Español", "日本語"];
    public List<string> ScanSensitivities { get; } = ["Low", "Balanced", "High", "Maximum"];
    public List<string> ScanFrequencies { get; } = ["Daily", "Weekly", "Monthly"];
    public List<string> ScanDays { get; } = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
    public List<string> ScanTimes { get; } = ["12:00 AM", "01:00 AM", "02:00 AM", "03:00 AM", "04:00 AM", "05:00 AM", "06:00 AM", "07:00 AM", "08:00 AM", "09:00 AM", "10:00 AM", "11:00 AM", "12:00 PM", "01:00 PM", "02:00 PM", "03:00 PM", "04:00 PM", "05:00 PM", "06:00 PM", "07:00 PM", "08:00 PM", "09:00 PM", "10:00 PM", "11:00 PM"];
    public List<string> ScanTypes { get; } = ["Quick Scan", "Full Scan"];
    public List<string> Themes { get; } = ["System", "Light", "Dark"];
    public List<string> AccentColors { get; } = ["Blue", "Teal", "Green", "Purple"];

    public SettingsViewModel(
        MockDataService mockDataService,
        IThemeService themeService,
        ISettingsService? settingsService = null,
        ILocalizationService? localizationService = null)
    {
        _mockDataService = mockDataService;
        _themeService = themeService;
        _settingsService = settingsService;
        _localizationService = localizationService;

        SelectedElementTheme = _themeService.CurrentTheme;
        SyncThemeRadios();

        // MotionPreferences ile iki yönlü senkron başlangıçta.
        ReduceMotion = !MotionPreferences.Enabled;

        if (_settingsService != null)
        {
            var s = _settingsService.CurrentSettings;
            SelectedLanguage = s.SelectedLanguage;
            UseRealDefenderEngine = s.UseRealDefenderEngine;
            StartWithWindows = s.StartWithWindows;
            MinimizeToTray = s.MinimizeToTray;
            ShowNotifications = s.ShowNotifications;
            TelemetryEnabled = s.TelemetryEnabled;
            CompactMode = s.CompactMode;
            RealTimeProtection = s.RealTimeProtection;
            CloudProtection = s.CloudProtection;
            AutomaticSampleSubmission = s.AutomaticSampleSubmission;
            ScanSensitivity = s.ScanSensitivity;
            ThreatNotifications = s.ThreatNotifications;
            ScanCompleteNotifications = s.ScanCompleteNotifications;
            UpdateNotifications = s.UpdateNotifications;
            SoundAlerts = s.SoundAlerts;
            ScheduledScanEnabled = s.ScheduledScanEnabled;
            ScanFrequency = s.ScanFrequency;
        }

        Categories =
        [
            new SettingsCategory("general", "Genel", "\uE713"),
            new SettingsCategory("appearance", "Görünüm", "\uE790"),
            new SettingsCategory("scan", "Tarama", "\uE773"),
            new SettingsCategory("protection", "Koruma", "\uE72E"),
            new SettingsCategory("notifications", "Bildirimler", "\uEA8F"),
            new SettingsCategory("privacy", "Gizlilik", "\uE72E"),
            new SettingsCategory("about", "Hakkında", "\uE946"),
        ];

        SelectedCategory = Categories[0];

        LoadData();
    }

    private void LoadData()
    {
        ExcludedFiles =
        [
            @"C:\Program Files\MyApp\app.exe",
            @"C:\Users\John\Documents\whitelist.dll",
        ];

        ExcludedFolders =
        [
            @"C:\Development\Projects",
            @"C:\Games\Steam",
        ];
    }

    private void SyncThemeRadios()
    {
        IsLightThemeSelected = SelectedElementTheme == ElementTheme.Light;
        IsDarkThemeSelected = SelectedElementTheme == ElementTheme.Dark;
        IsSystemThemeSelected = SelectedElementTheme == ElementTheme.Default;
    }

    partial void OnSelectedElementThemeChanged(ElementTheme value)
    {
        _themeService.SetTheme(value);
        SyncThemeRadios();
        SelectedTheme = value switch
        {
            ElementTheme.Light => "Light",
            ElementTheme.Dark => "Dark",
            _ => "System"
        };
    }

    /// <summary>
    /// Faz 7: "Animasyonları Azalt" toggle → MotionPreferences.Enabled'ı set eder.
    /// Animasyon helper'ları ve hover efektleri bu flag'i kontrol ederek
    /// continuous/decorative efektleri atlar.
    /// </summary>
    partial void OnReduceMotionChanged(bool value)
    {
        MotionPreferences.Enabled = !value;
        _settingsService?.UpdateSettings(s => s.ReduceMotion = value);
    }

    partial void OnUseRealDefenderEngineChanged(bool value)
    {
        _settingsService?.UpdateSettings(s => s.UseRealDefenderEngine = value);
    }

    partial void OnSelectedLanguageChanged(string value)
    {
        _localizationService?.SetLanguage(value);
        _settingsService?.UpdateSettings(s => s.SelectedLanguage = value);
    }

    [RelayCommand]
    private void SetTheme(string? themeKey)
    {
        SelectedElementTheme = themeKey switch
        {
            "Light" => ElementTheme.Light,
            "Dark" => ElementTheme.Dark,
            _ => ElementTheme.Default
        };
    }

    [RelayCommand]
    private void SelectCategory(SettingsCategory? category)
    {
        if (category is not null)
        {
            SelectedCategory = category;
        }
    }

    [RelayCommand]
    private void AddExcludedFile()
    {
        ExcludedFiles.Add(@"C:\NewPath\newfile.exe");
    }

    [RelayCommand]
    private void AddExcludedFolder()
    {
        ExcludedFolders.Add(@"C:\NewPath\NewFolder");
    }

    [RelayCommand]
    private void RemoveExcludedFile(string path)
    {
        ExcludedFiles.Remove(path);
    }

    [RelayCommand]
    private void RemoveExcludedFolder(string path)
    {
        ExcludedFolders.Remove(path);
    }

    [RelayCommand]
    private void ResetAllSettings()
    {
        StartWithWindows = true;
        MinimizeToTray = true;
        ShowNotifications = true;
        SelectedLanguage = "Türkçe";
        TelemetryEnabled = false;
        RealTimeProtection = true;
        CloudProtection = true;
        AutomaticSampleSubmission = false;
        ScanSensitivity = "Balanced";
        ScanArchives = true;
        ScanRemovableDrives = true;
        ScanNetworkDrives = false;
        ThreatNotifications = true;
        ScanCompleteNotifications = true;
        UpdateNotifications = true;
        WeeklyReportNotifications = false;
        SoundAlerts = false;
        ScheduledScanEnabled = true;
        ScanFrequency = "Weekly";
        ScanDay = "Monday";
        ScanTime = "02:00 AM";
        ScheduledScanType = "Quick Scan";
        SelectedElementTheme = ElementTheme.Default;
        AccentColor = "Blue";
        SendUsageData = false;
        SendCrashReports = true;
        ParticipateInBeta = false;
    }

    [RelayCommand]
    private void ExportSettings()
    {
        // Mock
    }

    [RelayCommand]
    private void ImportSettings()
    {
        // Mock
    }

    [RelayCommand]
    private void CheckForUpdates()
    {
        // Mock
    }
}