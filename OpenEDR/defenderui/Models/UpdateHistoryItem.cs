namespace DefenderUI.Models;

public class UpdateHistoryItem
{
    public string Version { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public DateTime Date { get; set; }
    public string Size { get; set; } = string.Empty;
    public bool Success { get; set; }
}