namespace DefenderUI.Models;

public enum ScanType
{
    Quick,
    Full,
    Custom,
    USB
}

public enum ScanStatus
{
    NotStarted,
    Running,
    Paused,
    Completed,
    Cancelled
}

public class ScanResult
{
    public ScanType Type { get; set; }
    public ScanStatus Status { get; set; }
    public DateTime StartTime { get; set; }
    public DateTime? EndTime { get; set; }
    public TimeSpan Duration { get; set; }
    public int FilesScanned { get; set; }
    public int ThreatsFound { get; set; }
    public double Progress { get; set; }
    public string CurrentFile { get; set; } = string.Empty;
}