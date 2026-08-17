using System;

namespace DefenderUI.Helpers;

/// <summary>
/// Uygulama genelinde "reduced motion" tercihi için hafif singleton.
/// Animasyon yardımcıları bu flag'i kontrol ederek costly efektleri atlar.
///
/// Faz 7 — Settings > Görünüm > "Animasyonları Azalt" toggle'ı bu değeri set eder.
/// Değişiklik olduğunda <see cref="Changed"/> tetiklenir.
/// </summary>
public static class MotionPreferences
{
    private static bool _enabled = true;

    /// <summary>
    /// True ise animasyonlar çalışır, false ise reduced-motion moddadır.
    /// </summary>
    public static bool Enabled
    {
        get => _enabled;
        set
        {
            if (_enabled == value)
            {
                return;
            }
            _enabled = value;
            Changed?.Invoke(null, EventArgs.Empty);
        }
    }

    /// <summary>
    /// <see cref="Enabled"/> değeri değiştiğinde tetiklenir.
    /// </summary>
    public static event EventHandler? Changed;
}