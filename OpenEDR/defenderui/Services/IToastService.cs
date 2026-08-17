using System;

namespace DefenderUI.Services;

/// <summary>
/// Uygulama içi (in-app) toast bildirim ciddiyet seviyeleri.
/// </summary>
public enum ToastSeverity
{
    Info,
    Success,
    Warning,
    Error
}

/// <summary>
/// Tek bir toast bildirimini temsil eden immutable değer nesnesi.
/// </summary>
/// <param name="Title">Kısa, tek satırlık başlık.</param>
/// <param name="Body">Opsiyonel detay metni.</param>
/// <param name="Severity">Bildirim seviyesi.</param>
/// <param name="Duration">
/// Otomatik kapanma süresi. <c>null</c> ise host UI kendi default'unu kullanır.
/// </param>
public record ToastMessage(
    string Title,
    string? Body,
    ToastSeverity Severity,
    TimeSpan? Duration = null);

/// <summary>
/// Uygulama içi (OS toast DEĞİL) toast bildirim servisi. Shell veya host bir
/// UI bileşeni <see cref="ToastRequested"/> event'ini dinleyerek görsel
/// gösterimi üstlenir. Servis yalnızca mesaj iletimini soyutlar.
/// </summary>
public interface IToastService
{
    /// <summary>
    /// Yeni bir toast gösterilmesi istendiğinde tetiklenir.
    /// </summary>
    event EventHandler<ToastMessage>? ToastRequested;

    /// <summary>
    /// Belirtilen toast'u yayınlar.
    /// </summary>
    void Show(ToastMessage toast);

    void Info(string title, string? body = null);
    void Success(string title, string? body = null);
    void Warning(string title, string? body = null);
    void Error(string title, string? body = null);
}