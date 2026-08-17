using System;

namespace DefenderUI.Services;

public interface ILocalizationService
{
    string CurrentLanguage { get; }
    void SetLanguage(string languageCode);
    string GetString(string key);
    event EventHandler? LanguageChanged;
}
