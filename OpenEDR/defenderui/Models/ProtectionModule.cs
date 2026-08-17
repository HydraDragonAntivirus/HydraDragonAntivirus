using CommunityToolkit.Mvvm.ComponentModel;

namespace DefenderUI.Models;

public partial class ProtectionModule : ObservableObject
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Icon { get; set; } = string.Empty;

    [ObservableProperty]
    private bool _isEnabled;

    [ObservableProperty]
    private bool _hasIssue;

    [ObservableProperty]
    private string _issueDescription = string.Empty;
}