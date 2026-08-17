using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using DefenderUI.Models;
using DefenderUI.Services;
using Microsoft.UI.Dispatching;

namespace DefenderUI.ViewModels;

#pragma warning disable MVVMTK0045

/// <summary>
/// Scan sayfası ViewModel'i (Faz 4).
/// <see cref="IScanService"/> üzerinden async tarama simülasyonunu yönetir,
/// event'leri UI thread'ine marshal ederek observable property'lere yansıtır.
/// </summary>
public partial class ScanViewModel : ObservableObject, IDisposable
{
    private readonly MockDataService _mockDataService;
    private readonly IScanService _scanService;
    private readonly INavigationService? _navigationService;
    private readonly IToastService? _toastService;
    private readonly DispatcherQueue? _dispatcher;

    // ═════════════════════════════════════════════════════════════════
    // Mod seçimi
    // ═════════════════════════════════════════════════════════════════
    [ObservableProperty]
    private ScanMode _selectedMode = ScanMode.Quick;

    [ObservableProperty]
    private IReadOnlyList<ScanModeOption> _scanModes = [];

    // ═════════════════════════════════════════════════════════════════
    // Durum
    // ═════════════════════════════════════════════════════════════════
    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private bool _isPaused;

    [ObservableProperty]
    private double _progress;

    [ObservableProperty]
    private int _filesScanned;

    [ObservableProperty]
    private int _threatsFound;

    [ObservableProperty]
    private string _currentPath = string.Empty;

    [ObservableProperty]
    private string _elapsedText = "00:00";

    [ObservableProperty]
    private string _remainingText = "--:--";

    [ObservableProperty]
    private ScanCompletionInfo? _lastCompletionInfo;

    // ═════════════════════════════════════════════════════════════════
    // Custom paths
    // ═════════════════════════════════════════════════════════════════
    [ObservableProperty]
    private ObservableCollection<string> _customPaths = new();

    // ═════════════════════════════════════════════════════════════════
    // Computed
    // ═════════════════════════════════════════════════════════════════
    public bool HasLastCompletion => LastCompletionInfo is not null;

    public string ProgressText => ((int)Math.Round(Progress)).ToString(CultureInfo.InvariantCulture) + "%";

    public string SelectedModeTitle =>
        ScanModes.FirstOrDefault(m => m.Mode == SelectedMode)?.Title ?? SelectedMode.ToString();

    public string LastCompletionModeTitle
    {
        get
        {
            if (LastCompletionInfo is null) return string.Empty;
            return ScanModes.FirstOrDefault(m => m.Mode == LastCompletionInfo.Mode)?.Title
                ?? LastCompletionInfo.Mode.ToString();
        }
    }

    public string LastCompletionDurationText
    {
        get
        {
            if (LastCompletionInfo is null) return string.Empty;
            var d = LastCompletionInfo.Duration;
            return d.TotalMinutes >= 1
                ? $"{(int)d.TotalMinutes} dk {d.Seconds} sn"
                : $"{d.Seconds} sn";
        }
    }

    public string LastCompletionDateText =>
        LastCompletionInfo?.CompletedAt.ToString("dd MMM yyyy HH:mm", CultureInfo.CurrentCulture) ?? string.Empty;

    public bool IsCustomMode => SelectedMode == ScanMode.Custom;

    public string PauseResumeText => IsPaused ? "Devam Ettir" : "Duraklat";

    public string PauseResumeGlyph => IsPaused ? "\uE768" : "\uE769";

    partial void OnProgressChanged(double value) => OnPropertyChanged(nameof(ProgressText));
    partial void OnSelectedModeChanged(ScanMode value)
    {
        OnPropertyChanged(nameof(SelectedModeTitle));
        OnPropertyChanged(nameof(IsCustomMode));
    }
    partial void OnScanModesChanged(IReadOnlyList<ScanModeOption> value)
    {
        OnPropertyChanged(nameof(SelectedModeTitle));
        OnPropertyChanged(nameof(LastCompletionModeTitle));
    }
    partial void OnLastCompletionInfoChanged(ScanCompletionInfo? value)
    {
        OnPropertyChanged(nameof(HasLastCompletion));
        OnPropertyChanged(nameof(LastCompletionModeTitle));
        OnPropertyChanged(nameof(LastCompletionDurationText));
        OnPropertyChanged(nameof(LastCompletionDateText));
    }
    partial void OnIsPausedChanged(bool value)
    {
        OnPropertyChanged(nameof(PauseResumeText));
        OnPropertyChanged(nameof(PauseResumeGlyph));
    }

    // ═════════════════════════════════════════════════════════════════
    // Ctor
    // ═════════════════════════════════════════════════════════════════
    public ScanViewModel(
        MockDataService mockDataService,
        IScanService scanService,
        INavigationService? navigationService = null,
        IToastService? toastService = null)
    {
        _mockDataService = mockDataService;
        _scanService = scanService;
        _navigationService = navigationService;
        _toastService = toastService;
        _dispatcher = DispatcherQueue.GetForCurrentThread();

        ScanModes = _mockDataService.GetScanModeOptions();

        _scanService.ProgressChanged += OnScanProgressChanged;
        _scanService.ScanCompleted += OnScanCompleted;
        _scanService.ScanCancelled += OnScanCancelled;
    }

    /// <summary>
    /// Navigation parametresine göre başlangıç modunu ayarlar ("quick" / "full" / "custom" / "removable").
    /// </summary>
    public void ApplyNavigationParameter(object? parameter)
    {
        if (parameter is string key && !string.IsNullOrWhiteSpace(key))
        {
            SelectedMode = key.ToLowerInvariant() switch
            {
                "quick" => ScanMode.Quick,
                "full" => ScanMode.Full,
                "custom" => ScanMode.Custom,
                "removable" or "usb" => ScanMode.Removable,
                _ => SelectedMode
            };
        }
    }

    // ═════════════════════════════════════════════════════════════════
    // Commands
    // ═════════════════════════════════════════════════════════════════
    [RelayCommand]
    private void SelectMode(ScanMode mode)
    {
        if (IsScanning) return;
        SelectedMode = mode;
    }

    [RelayCommand]
    private async System.Threading.Tasks.Task StartScanAsync()
    {
        if (IsScanning) return;

        // Reset state
        Progress = 0;
        FilesScanned = 0;
        ThreatsFound = 0;
        CurrentPath = string.Empty;
        ElapsedText = "00:00";
        RemainingText = "--:--";
        IsPaused = false;
        IsScanning = true;

        IEnumerable<string>? customPaths = SelectedMode == ScanMode.Custom && CustomPaths.Count > 0
            ? CustomPaths.ToList()
            : null;

        try
        {
            await _scanService.StartScanAsync(SelectedMode, customPaths).ConfigureAwait(false);
        }
        catch
        {
            RunOnUi(() => IsScanning = false);
        }
    }

    [RelayCommand]
    private void CancelScan()
    {
        if (!IsScanning) return;
        _scanService.CancelScan();
    }

    [RelayCommand]
    private void PauseResume()
    {
        if (!IsScanning) return;

        if (IsPaused)
        {
            _scanService.ResumeScan();
            IsPaused = false;
        }
        else
        {
            _scanService.PauseScan();
            IsPaused = true;
        }
    }

    [RelayCommand]
    private void AddCustomPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        if (CustomPaths.Contains(path)) return;
        CustomPaths.Add(path);
    }

    [RelayCommand]
    private void RemoveCustomPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        CustomPaths.Remove(path);
    }

    [RelayCommand]
    private void ViewResults() => _navigationService?.NavigateTo("reports");

    // ═════════════════════════════════════════════════════════════════
    // Scan service event handlers (background thread — dispatch to UI)
    // ═════════════════════════════════════════════════════════════════
    private void OnScanProgressChanged(object? sender, ScanProgressInfo e)
    {
        RunOnUi(() =>
        {
            Progress = e.PercentComplete;
            FilesScanned = e.FilesScanned;
            ThreatsFound = e.ThreatsFound;
            CurrentPath = e.CurrentPath;
            ElapsedText = FormatTime(e.Elapsed);
            RemainingText = FormatTime(e.EstimatedRemaining);
        });
    }

    private void OnScanCompleted(object? sender, ScanCompletionInfo e)
    {
        RunOnUi(() =>
        {
            IsScanning = false;
            IsPaused = false;
            Progress = 100;
            LastCompletionInfo = e;

            var body = e.ThreatsFound > 0
                ? $"{e.FilesScanned:N0} dosya tarandı, {e.ThreatsFound} tehdit bulundu."
                : $"{e.FilesScanned:N0} dosya tarandı, tehdit bulunamadı.";
            _toastService?.Success("Tarama tamamlandı", body);
        });
    }

    private void OnScanCancelled(object? sender, EventArgs e)
    {
        RunOnUi(() =>
        {
            IsScanning = false;
            IsPaused = false;
            _toastService?.Info("Tarama iptal edildi", "Tarama kullanıcı tarafından durduruldu.");
        });
    }

    // ═════════════════════════════════════════════════════════════════
    // Helpers
    // ═════════════════════════════════════════════════════════════════
    private void RunOnUi(Action action)
    {
        // K3: _dispatcher ctor sırasında UI thread dışında resolve edilirse null döner.
        // Bu durumda fallback olarak çağrı anında tekrar dene; yine yoksa doğrudan çalıştır
        // (çağıran thread zaten UI olabilir) ve hataları yut.
        var dispatcher = _dispatcher ?? Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread();
        if (dispatcher is null)
        {
            try { action(); }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine(ex); }
            return;
        }
        if (dispatcher.HasThreadAccess)
        {
            action();
        }
        else
        {
            dispatcher.TryEnqueue(() => action());
        }
    }

    private static string FormatTime(TimeSpan span)
    {
        if (span < TimeSpan.Zero) span = TimeSpan.Zero;
        if (span.TotalHours >= 1)
        {
            return $"{(int)span.TotalHours:D2}:{span.Minutes:D2}:{span.Seconds:D2}";
        }
        return $"{span.Minutes:D2}:{span.Seconds:D2}";
    }

    public void Dispose()
    {
        _scanService.ProgressChanged -= OnScanProgressChanged;
        _scanService.ScanCompleted -= OnScanCompleted;
        _scanService.ScanCancelled -= OnScanCancelled;
    }
}

#pragma warning restore MVVMTK0045