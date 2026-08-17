namespace DefenderUI.Models;

public enum ProtectionState
{
    Protected,
    AtRisk,
    AttentionNeeded,
    Scanning
}

public class ProtectionStatus
{
    public ProtectionState State { get; set; }
    public int SecurityScore { get; set; }
    public string StatusMessage { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}