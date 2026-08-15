using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DefenderUI.Models;
using DefenderUI.Services;

namespace DefenderUI.ViewModels;

public partial class QuarantineViewModel : ObservableObject
{
    private readonly MockDataService _mockDataService;

    [ObservableProperty]
    private ObservableCollection<ThreatInfo> _quarantinedItems = [];

    [ObservableProperty]
    private ObservableCollection<ThreatInfo> _filteredItems = [];

    [ObservableProperty]
    private string _searchQuery = string.Empty;

    [ObservableProperty]
    private int _selectedRiskFilterIndex;

    [ObservableProperty]
    private int _selectedDateFilterIndex = 3;

    [ObservableProperty]
    private int _totalQuarantined;

    [ObservableProperty]
    private int _criticalCount;

    [ObservableProperty]
    private int _highCount;

    [ObservableProperty]
    private int _mediumCount;

    [ObservableProperty]
    private int _lowCount;

    [ObservableProperty]
    private bool _isAllSelected;

    [ObservableProperty]
    private int _selectedCount;

    [ObservableProperty]
    private bool _hasFilteredItems;

    public QuarantineViewModel(MockDataService mockDataService)
    {
        _mockDataService = mockDataService;
        LoadQuarantinedItems();
    }

    private void LoadQuarantinedItems()
    {
        var items = _mockDataService.GetQuarantinedItems();
        QuarantinedItems = new ObservableCollection<ThreatInfo>(items);
        UpdateStatistics();
        ApplyFilters();
    }

    private void UpdateStatistics()
    {
        TotalQuarantined = QuarantinedItems.Count;
        CriticalCount = QuarantinedItems.Count(i => i.RiskLevel == RiskLevel.Critical);
        HighCount = QuarantinedItems.Count(i => i.RiskLevel == RiskLevel.High);
        MediumCount = QuarantinedItems.Count(i => i.RiskLevel == RiskLevel.Medium);
        LowCount = QuarantinedItems.Count(i => i.RiskLevel == RiskLevel.Low);
    }

    partial void OnSearchQueryChanged(string value) => ApplyFilters();

    partial void OnSelectedRiskFilterIndexChanged(int value) => ApplyFilters();

    partial void OnSelectedDateFilterIndexChanged(int value) => ApplyFilters();

    partial void OnIsAllSelectedChanged(bool value)
    {
        foreach (var item in FilteredItems)
        {
            item.IsSelected = value;
        }

        UpdateSelectedCount();
    }

    [RelayCommand]
    private void ApplyFilters()
    {
        var filtered = QuarantinedItems.AsEnumerable();

        // Search filter
        if (!string.IsNullOrWhiteSpace(SearchQuery))
        {
            var query = SearchQuery.Trim();
            filtered = filtered.Where(i =>
                i.ThreatName.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                i.FilePath.Contains(query, StringComparison.OrdinalIgnoreCase));
        }

        // Risk level filter (0=All, 1=Critical, 2=High, 3=Medium, 4=Low)
        filtered = SelectedRiskFilterIndex switch
        {
            1 => filtered.Where(i => i.RiskLevel == RiskLevel.Critical),
            2 => filtered.Where(i => i.RiskLevel == RiskLevel.High),
            3 => filtered.Where(i => i.RiskLevel == RiskLevel.Medium),
            4 => filtered.Where(i => i.RiskLevel == RiskLevel.Low),
            _ => filtered
        };

        // Date filter (0=Last 24h, 1=Last 7 days, 2=Last 30 days, 3=All Time)
        var now = DateTime.Now;
        filtered = SelectedDateFilterIndex switch
        {
            0 => filtered.Where(i => i.DetectionDate >= now.AddHours(-24)),
            1 => filtered.Where(i => i.DetectionDate >= now.AddDays(-7)),
            2 => filtered.Where(i => i.DetectionDate >= now.AddDays(-30)),
            _ => filtered
        };

        FilteredItems = new ObservableCollection<ThreatInfo>(filtered);
        HasFilteredItems = FilteredItems.Count > 0;
        UpdateSelectedCount();
    }

    public void UpdateSelectedCount()
    {
        SelectedCount = FilteredItems.Count(i => i.IsSelected);
    }

    [RelayCommand]
    private void RestoreItem(ThreatInfo item)
    {
        QuarantinedItems.Remove(item);
        FilteredItems.Remove(item);
        UpdateStatistics();
        HasFilteredItems = FilteredItems.Count > 0;
        UpdateSelectedCount();
    }

    [RelayCommand]
    private void DeleteItem(ThreatInfo item)
    {
        QuarantinedItems.Remove(item);
        FilteredItems.Remove(item);
        UpdateStatistics();
        HasFilteredItems = FilteredItems.Count > 0;
        UpdateSelectedCount();
    }

    [RelayCommand]
    private void RestoreSelected()
    {
        var selectedItems = FilteredItems.Where(i => i.IsSelected).ToList();
        foreach (var item in selectedItems)
        {
            QuarantinedItems.Remove(item);
            FilteredItems.Remove(item);
        }

        UpdateStatistics();
        HasFilteredItems = FilteredItems.Count > 0;
        UpdateSelectedCount();
    }

    [RelayCommand]
    private void DeleteSelected()
    {
        var selectedItems = FilteredItems.Where(i => i.IsSelected).ToList();
        foreach (var item in selectedItems)
        {
            QuarantinedItems.Remove(item);
            FilteredItems.Remove(item);
        }

        UpdateStatistics();
        HasFilteredItems = FilteredItems.Count > 0;
        UpdateSelectedCount();
    }

    [RelayCommand]
    private void DeleteAll()
    {
        QuarantinedItems.Clear();
        FilteredItems.Clear();
        UpdateStatistics();
        HasFilteredItems = false;
        UpdateSelectedCount();
    }
}