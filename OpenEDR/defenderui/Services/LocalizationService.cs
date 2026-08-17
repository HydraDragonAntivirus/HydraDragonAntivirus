using System;
using System.Collections.Generic;

namespace DefenderUI.Services;

public class LocalizationService : ILocalizationService
{
    private string _currentLanguage = "Türkçe";
    private readonly Dictionary<string, Dictionary<string, string>> _translations = new(StringComparer.OrdinalIgnoreCase);

    public string CurrentLanguage => _currentLanguage;
    public event EventHandler? LanguageChanged;

    public LocalizationService()
    {
        InitializeTranslations();
    }

    private void InitializeTranslations()
    {
        var tr = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "Dashboard_Title", "Kontrol Paneli" },
            { "Status_Protected", "Cihazınız Korunuyor" },
            { "Status_Protected_Desc", "Tüm güvenlik modülleri aktif ve güncel." },
            { "QuickScan_Button", "Hızlı Tarama Başlat" },
            { "FullScan_Button", "Tam Tarama Başlat" },
            { "Settings_Title", "Ayarlar" },
            { "Language_Label", "Uygulama Dili" },
            { "RealDefenderMode_Label", "Gerçek Windows Defender Modunu Kullan" }
        };

        var en = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "Dashboard_Title", "Dashboard" },
            { "Status_Protected", "Your device is protected" },
            { "Status_Protected_Desc", "All security features are active and up to date." },
            { "QuickScan_Button", "Start Quick Scan" },
            { "FullScan_Button", "Start Full Scan" },
            { "Settings_Title", "Settings" },
            { "Language_Label", "Application Language" },
            { "RealDefenderMode_Label", "Use Real Windows Defender Engine" }
        };

        _translations["Türkçe"] = tr;
        _translations["tr-TR"] = tr;
        _translations["English"] = en;
        _translations["en-US"] = en;
    }

    public void SetLanguage(string languageCode)
    {
        if (_currentLanguage != languageCode)
        {
            _currentLanguage = languageCode;
            LanguageChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public string GetString(string key)
    {
        if (_translations.TryGetValue(_currentLanguage, out var langDict) && langDict.TryGetValue(key, out var val))
        {
            return val;
        }
        if (_translations["English"].TryGetValue(key, out var fallbackVal))
        {
            return fallbackVal;
        }
        return key;
    }
}
