using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DefenderUI.Models;
using DefenderUI.Services;

namespace DefenderUI.ViewModels;

public partial class ReportsViewModel : ObservableObject
{
    private readonly MockDataService _mockDataService;

    [ObservableProperty]
    private string _selectedPeriod = "Last 7 Days";

    [ObservableProperty]
    private int _totalScans;

    [ObservableProperty]
    private int _totalThreatsDetected;

    [ObservableProperty]
    private int _totalThreatsBlocked;

    [ObservableProperty]
    private int _totalFilesScanned;

    [ObservableProperty]
    private ObservableCollection<DailyThreatData> _weeklyThreats = [];

    [ObservableProperty]
    private ObservableCollection<ScanResult> _recentScans = [];

    [ObservableProperty]
    private int _trojanCount;

    [ObservableProperty]
    private int _adwareCount;

    [ObservableProperty]
    private int _spywareCount;

    [ObservableProperty]
    private int _pupCount;

    [ObservableProperty]
    private int _ransomwareCount;

    [ObservableProperty]
    private int _daysProtected;

    [ObservableProperty]
    private double _averageScanTime;

    [ObservableProperty]
    private int _maxThreatValue;

    public ReportsViewModel(MockDataService mockDataService)
    {
        _mockDataService = mockDataService;
        LoadReportData();
    }

    private void LoadReportData()
    {
        TotalScans = 12;
        TotalThreatsDetected = 47;
        TotalThreatsBlocked = 143;
        TotalFilesScanned = 284591;

        TrojanCount = 18;
        AdwareCount = 12;
        SpywareCount = 8;
        PupCount = 5;
        RansomwareCount = 4;

        DaysProtected = 45;
        AverageScanTime = 2.08;

        WeeklyThreats =
        [
            new DailyThreatData { Day = "Mon", Threats = 5, Blocked = 4 },
            new DailyThreatData { Day = "Tue", Threats = 2, Blocked = 2 },
            new DailyThreatData { Day = "Wed", Threats = 8, Blocked = 7 },
            new DailyThreatData { Day = "Thu", Threats = 3, Blocked = 3 },
            new DailyThreatData { Day = "Fri", Threats = 7, Blocked = 6 },
            new DailyThreatData { Day = "Sat", Threats = 1, Blocked = 1 },
            new DailyThreatData { Day = "Sun", Threats = 4, Blocked = 3 }
        ];

        MaxThreatValue = 8;

        RecentScans = new ObservableCollection<ScanResult>(_mockDataService.GetScanHistory());
    }

    [RelayCommand]
    private void ExportReport()
    {
        // UI-only placeholder
    }

    [RelayCommand]
    private void ExportCsv()
    {
        // UI placeholder — ileride gerçek dosya yazma.
    }

    [RelayCommand]
    private void ChangePeriod(string period)
    {
        SelectedPeriod = period;

        switch (period)
        {
            case "Last 30 Days":
                TotalScans = 38;
                TotalThreatsDetected = 124;
                TotalThreatsBlocked = 389;
                TotalFilesScanned = 1245890;
                break;
            case "Last 90 Days":
                TotalScans = 102;
                TotalThreatsDetected = 312;
                TotalThreatsBlocked = 987;
                TotalFilesScanned = 3892456;
                break;
            default:
                TotalScans = 12;
                TotalThreatsDetected = 47;
                TotalThreatsBlocked = 143;
                TotalFilesScanned = 284591;
                break;
        }
    }

    public int TotalThreatDistribution => TrojanCount + AdwareCount + SpywareCount + PupCount + RansomwareCount;
}