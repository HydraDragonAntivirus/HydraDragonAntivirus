namespace DefenderUI.Models;

public class SystemHealthInfo
{
    public int HealthScore { get; set; }
    public double CpuImpact { get; set; }
    public double MemoryUsage { get; set; }
    public bool BackgroundProtection { get; set; }
    public bool AutoUpdates { get; set; }
    public bool SecureBrowser { get; set; }
    public bool SafeNetwork { get; set; }
}