using DefenderUI.Services;

namespace DefenderUI.Models;

/// <summary>
/// Scan sayfasındaki mod seçim kartları için veri modeli (Faz 4).
/// </summary>
/// <param name="Mode">Tarama modu enum değeri.</param>
/// <param name="Glyph">Segoe Fluent Icons glyph kodu.</param>
/// <param name="Title">Mod başlığı (yerelleştirilmiş).</param>
/// <param name="Description">Kısa açıklama (1-2 satır).</param>
/// <param name="EstimatedDuration">Tahmini süre metni (örn. "~1-2 dk").</param>
public record ScanModeOption(
    ScanMode Mode,
    string Glyph,
    string Title,
    string Description,
    string EstimatedDuration);