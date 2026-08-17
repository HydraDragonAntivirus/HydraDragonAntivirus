using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DefenderUI.Models;
using DefenderUI.Services;
using Microsoft.UI.Dispatching;

namespace DefenderUI.ViewModels;

public partial class UpdateViewModel : ObservableObject
{
    private readonly MockDataService _mockDataService;
    private DispatcherQueueTimer? _updateTimer;
    private DispatcherQueue? _dispatcherQueue;

    [ObservableProperty]
    private string _virusDefinitionVersion = "2026.04.17.001";

    [ObservableProperty]
    private string _appVersion = "1.2.0";

    [ObservableProperty]
    private DateTime _lastUpdateDate;

    [ObservableProperty]
    private bool _isUpdateAvailable = true;

    [ObservableProperty]
    private string _availableUpdateVersion = "1.3.0";

    [ObservableProperty]
    private string _updateSize = "45.2 MB";

    [ObservableProperty]
    private bool _isUpdating;

    [ObservableProperty]
    private double _updateProgress;

    [ObservableProperty]
    private string _updateStatusText = "Update available";

    [ObservableProperty]
    private bool _isUpdateComplete;

    [ObservableProperty]
    private ObservableCollection<UpdateHistoryItem> _updateHistory = [];

    [ObservableProperty]
    private bool _autoUpdateEnabled = true;

    [ObservableProperty]
    private bool _autoDefinitionUpdate = true;

    [ObservableProperty]
    private bool _meteredConnectionUpdate;

    private readonly IUpdateService? _updateService;

    public UpdateViewModel(MockDataService mockDataService, IUpdateService? updateService = null)
    {
        _mockDataService = mockDataService;
        _updateService = updateService;
        LastUpdateDate = DateTime.Now.AddHours(-8);
        LoadUpdateHistory();
    }

    public void SetDispatcherQueue(DispatcherQueue dispatcherQueue)
    {
        _dispatcherQueue = dispatcherQueue;
    }

    private void LoadUpdateHistory()
    {
        UpdateHistory =
        [
            new UpdateHistoryItem
            {
                Version = "2026.04.17.001",
                Type = "Virus Definitions",
                Date = DateTime.Now.AddHours(-8),
                Size = "12 MB",
                Success = true
            },
            new UpdateHistoryItem
            {
                Version = "v1.2.0",
                Type = "App Update",
                Date = DateTime.Now.AddDays(-7),
                Size = "38 MB",
                Success = true
            },
            new UpdateHistoryItem
            {
                Version = "2026.04.10.003",
                Type = "Virus Definitions",
                Date = DateTime.Now.AddDays(-7),
                Size = "11 MB",
                Success = true
            },
            new UpdateHistoryItem
            {
                Version = "v1.1.5",
                Type = "Security Patch",
                Date = DateTime.Now.AddDays(-12),
                Size = "8 MB",
                Success = true
            },
            new UpdateHistoryItem
            {
                Version = "2026.04.03.001",
                Type = "Virus Definitions",
                Date = DateTime.Now.AddDays(-14),
                Size = "10 MB",
                Success = true
            }
        ];
    }

    [RelayCommand]
    private void CheckForUpdates()
    {
        IsUpdateAvailable = true;
        AvailableUpdateVersion = "1.3.0";
        UpdateStatusText = "Update available";
        IsUpdateComplete = false;
    }

    [RelayCommand]
    private void StartUpdate()
    {
        if (_dispatcherQueue is null)
        {
            return;
        }

        IsUpdating = true;
        IsUpdateComplete = false;
        UpdateProgress = 0;
        UpdateStatusText = "Downloading...";

        _updateTimer = _dispatcherQueue.CreateTimer();
        _updateTimer.Interval = TimeSpan.FromMilliseconds(100);
        _updateTimer.Tick += OnUpdateTimerTick;
        _updateTimer.Start();
    }

    [RelayCommand]
    private void CancelUpdate()
    {
        StopTimer();
        IsUpdating = false;
        UpdateProgress = 0;
        UpdateStatusText = "Update cancelled";
    }

    private void OnUpdateTimerTick(DispatcherQueueTimer sender, object args)
    {
        UpdateProgress += Random.Shared.Next(1, 3);

        if (UpdateProgress < 40)
        {
            UpdateStatusText = $"Downloading... {UpdateProgress:F0}%";
        }
        else if (UpdateProgress < 80)
        {
            UpdateStatusText = $"Installing... {UpdateProgress:F0}%";
        }
        else if (UpdateProgress < 100)
        {
            UpdateStatusText = $"Finalizing... {UpdateProgress:F0}%";
        }
        else
        {
            UpdateProgress = 100;
            StopTimer();

            IsUpdating = false;
            IsUpdateComplete = true;
            IsUpdateAvailable = false;
            UpdateStatusText = "Update completed successfully!";
            AppVersion = AvailableUpdateVersion;
        }
    }

    private void StopTimer()
    {
        if (_updateTimer is not null)
        {
            _updateTimer.Stop();
            _updateTimer.Tick -= OnUpdateTimerTick;
            _updateTimer = null;
        }
    }
}