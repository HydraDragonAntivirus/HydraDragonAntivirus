namespace DefenderUI.Models;

public enum ActivityType
{
    ThreatBlocked,
    ScanCompleted,
    DatabaseUpdated,
    FileQuarantined,
    ProtectionEnabled,
    ProtectionDisabled,
    Warning
}

public class ActivityLogItem
{
    public ActivityType Type { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
}