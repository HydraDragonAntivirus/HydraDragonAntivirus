using System;
using System.IO;
using System.Text.Json;
using DefenderUI.Models;

namespace DefenderUI.Services;

public class SettingsService : ISettingsService
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private readonly string _filePath;
    private readonly object _lockObj = new();

    public AppSettings CurrentSettings { get; private set; } = new();

    public SettingsService()
    {
        var appDataFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "HydraDragonAntivirus");
        if (!Directory.Exists(appDataFolder))
        {
            Directory.CreateDirectory(appDataFolder);
        }
        _filePath = Path.Combine(appDataFolder, "user_settings.json");
        Load();
    }

    public SettingsService(string customFilePath)
    {
        _filePath = customFilePath;
        Load();
    }

    public void Load()
    {
        lock (_lockObj)
        {
            try
            {
                if (File.Exists(_filePath))
                {
                    var json = File.ReadAllText(_filePath);
                    var settings = JsonSerializer.Deserialize<AppSettings>(json, JsonOptions);
                    if (settings != null)
                    {
                        CurrentSettings = settings;
                        return;
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to load settings: {ex.Message}");
            }
            CurrentSettings = new AppSettings();
        }
    }

    public void Save()
    {
        lock (_lockObj)
        {
            try
            {
                var directory = Path.GetDirectoryName(_filePath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }
                var json = JsonSerializer.Serialize(CurrentSettings, JsonOptions);
                File.WriteAllText(_filePath, json);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to save settings: {ex.Message}");
            }
        }
    }

    public void UpdateSettings(Action<AppSettings> updateAction)
    {
        lock (_lockObj)
        {
            updateAction(CurrentSettings);
            Save();
        }
    }
}
