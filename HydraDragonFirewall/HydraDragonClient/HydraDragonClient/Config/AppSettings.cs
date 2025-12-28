using System;
using System.IO;
using System.Text.Json;

namespace HydraDragonClient.Config
{
    /// <summary>
    /// Application settings for HydraDragon Remote Desktop
    /// </summary>
    public class AppSettings
    {
        public int Port { get; set; } = 9876;
        public int ScreenFps { get; set; } = 15;
        public int JpegQuality { get; set; } = 75;
        public bool EnableMouse { get; set; } = true;
        public string? LastConnectedIp { get; set; }
        
        private static readonly string SettingsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "HydraDragonClient",
            "settings.json"
        );

        public static AppSettings Load()
        {
            try
            {
                if (File.Exists(SettingsPath))
                {
                    var json = File.ReadAllText(SettingsPath);
                    return JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
                }
            }
            catch { }
            return new AppSettings();
        }

        public void Save()
        {
            try
            {
                var dir = Path.GetDirectoryName(SettingsPath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    Directory.CreateDirectory(dir);
                    
                var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(SettingsPath, json);
            }
            catch { }
        }
    }
}
