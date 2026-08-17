namespace DefenderUI.Models;

public class DailyThreatData
{
    public string Day { get; set; } = string.Empty;
    public int Threats { get; set; }
    public int Blocked { get; set; }
}