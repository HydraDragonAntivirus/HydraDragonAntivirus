namespace DefenderUI.Models;

/// <summary>
/// Dashboard "Hızlı Eylemler" grid'indeki bir FeatureTileCard için veri modeli.
/// </summary>
/// <param name="Glyph">Segoe Fluent Icons glyph kodu (örn. "\uE72E").</param>
/// <param name="Title">Kart başlığı.</param>
/// <param name="Description">Kısa açıklama (1-2 satır).</param>
/// <param name="BadgeText">Opsiyonel pill rozet metni (örn. "Yeni"). Null ise rozet gizlenir.</param>
/// <param name="NavigateKey">
/// <see cref="Services.INavigationService"/> için hedef sayfa anahtarı
/// (örn. "scan", "update", "quarantine", "reports", "protection", "privacy").
/// </param>
public record FeatureTileData(
    string Glyph,
    string Title,
    string Description,
    string? BadgeText,
    string NavigateKey);