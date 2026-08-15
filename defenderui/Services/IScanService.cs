using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace DefenderUI.Services;

/// <summary>
/// Tarama modları (Faz 4).
/// </summary>
public enum ScanMode
{
    Quick,
    Full,
    Custom,
    Removable
}

/// <summary>
/// Aktif tarama sırasında yayınlanan ilerleme bilgisi.
/// </summary>
public record ScanProgressInfo(
    double PercentComplete,
    int FilesScanned,
    int ThreatsFound,
    string CurrentPath,
    TimeSpan Elapsed,
    TimeSpan EstimatedRemaining);

/// <summary>
/// Tarama tamamlandığında yayınlanan özet bilgi.
/// </summary>
public record ScanCompletionInfo(
    ScanMode Mode,
    int FilesScanned,
    int ThreatsFound,
    TimeSpan Duration,
    DateTime CompletedAt);

/// <summary>
/// Mock asenkron tarama simülasyonu servisi (Faz 4).
/// UI thread'e dokunmaz; event'ler consumer tarafta Dispatcher ile marshal edilir.
/// </summary>
public interface IScanService
{
    /// <summary>
    /// Aktif bir tarama var mı?
    /// </summary>
    bool IsScanning { get; }

    /// <summary>
    /// Devam eden taramanın modu (varsa).
    /// </summary>
    ScanMode? CurrentMode { get; }

    /// <summary>
    /// ~100ms'de bir ilerleme olayı.
    /// </summary>
    event EventHandler<ScanProgressInfo>? ProgressChanged;

    /// <summary>
    /// Tarama başarıyla tamamlandığında.
    /// </summary>
    event EventHandler<ScanCompletionInfo>? ScanCompleted;

    /// <summary>
    /// Tarama kullanıcı tarafından iptal edildiğinde.
    /// </summary>
    event EventHandler? ScanCancelled;

    /// <summary>
    /// Yeni bir tarama başlatır. Zaten çalışıyor ise no-op.
    /// </summary>
    Task StartScanAsync(ScanMode mode, IEnumerable<string>? customPaths = null);

    /// <summary>
    /// Devam eden taramayı iptal eder.
    /// </summary>
    void CancelScan();

    /// <summary>
    /// Devam eden taramayı duraklatır (ilerleme donar).
    /// </summary>
    void PauseScan();

    /// <summary>
    /// Duraklatılmış taramayı devam ettirir.
    /// </summary>
    void ResumeScan();
}