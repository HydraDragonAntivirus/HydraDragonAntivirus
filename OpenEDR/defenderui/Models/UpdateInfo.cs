namespace DefenderUI.Models;

public class UpdateInfo
{
    public string VirusDefinitionVersion { get; set; } = string.Empty;
    public string AppVersion { get; set; } = string.Empty;
    public DateTime LastUpdateDate { get; set; }
    public bool IsUpdateAvailable { get; set; }
    public double UpdateProgress { get; set; }
    public string UpdateSize { get; set; } = string.Empty;
}