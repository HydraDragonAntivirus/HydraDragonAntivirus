namespace DefenderUI.Models;

public enum RiskLevel
{
    Low,
    Medium,
    High,
    Critical
}

public class ThreatInfo : CommunityToolkit.Mvvm.ComponentModel.ObservableObject
{
    public string ThreatName { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public DateTime DetectionDate { get; set; }
    public RiskLevel RiskLevel { get; set; }
    public string ActionTaken { get; set; } = string.Empty;
    public bool IsQuarantined { get; set; }

    private bool _isSelected;
    public bool IsSelected
    {
        get => _isSelected;
        set => SetProperty(ref _isSelected, value);
    }
}