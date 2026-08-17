using DefenderUI.Models;

namespace DefenderUI.Services;

public interface ISettingsService
{
    AppSettings CurrentSettings { get; }
    void Load();
    void Save();
    void UpdateSettings(System.Action<AppSettings> updateAction);
}
