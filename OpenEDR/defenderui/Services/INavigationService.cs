using System;
using Microsoft.UI.Xaml.Controls;

namespace DefenderUI.Services;

/// <summary>
/// Uygulama içi sayfa navigasyon servisi. Shell (MainWindow) içindeki
/// <see cref="Frame"/> üzerinden sayfa geçişlerini, history yönetimini ve
/// <see cref="Navigated"/> olay akışını soyutlar.
/// </summary>
public interface INavigationService
{
    /// <summary>
    /// Navigasyonun yönlendirileceği host Frame. Shell (MainWindow) tarafından
    /// başlangıçta set edilir.
    /// </summary>
    Frame? Frame { get; set; }

    /// <summary>
    /// Geri gidilebilir bir history olup olmadığını döndürür.
    /// </summary>
    bool CanGoBack { get; }

    /// <summary>
    /// Her başarılı navigasyondan sonra tetiklenir (aktif sayfa değiştiğinde).
    /// </summary>
    event EventHandler? Navigated;

    /// <summary>
    /// Verilen anahtar (örn. "dashboard") ile kayıtlı sayfaya geçer.
    /// Aynı sayfa zaten açıksa no-op döner.
    /// </summary>
    /// <returns>Navigasyon başarılı ise <c>true</c>.</returns>
    bool NavigateTo(string pageKey, object? parameter = null);

    /// <summary>
    /// Mümkünse bir önceki sayfaya geri gider.
    /// </summary>
    bool GoBack();

    /// <summary>
    /// Frame back-stack'ini temizler.
    /// </summary>
    void ClearHistory();
}