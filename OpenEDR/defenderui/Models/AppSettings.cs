using System.Collections.Generic;

namespace DefenderUI.Models;

public class AppSettings
{
    public string SelectedLanguage { get; set; } = "Türkçe";
    public bool UseRealDefenderEngine { get; set; } = false;

    // General
    public bool StartWithWindows { get; set; } = true;
    public bool MinimizeToTray { get; set; } = true;
    public bool ShowNotifications { get; set; } = true;
    public bool TelemetryEnabled { get; set; } = false;

    // Appearance / Theme
    public string SelectedTheme { get; set; } = "System"; // System, Light, Dark
    public bool CompactMode { get; set; } = false;
    public bool ReduceMotion { get; set; } = false;

    // Protection
    public bool RealTimeProtection { get; set; } = true;
    public bool CloudProtection { get; set; } = true;
    public bool AutomaticSampleSubmission { get; set; } = false;
    public string ScanSensitivity { get; set; } = "Balanced";
    public bool ScanArchives { get; set; } = true;
    public bool ScanRemovableDrives { get; set; } = true;
    public bool ScanNetworkDrives { get; set; } = false;

    // Notifications
    public bool ThreatNotifications { get; set; } = true;
    public bool ScanCompleteNotifications { get; set; } = true;
    public bool UpdateNotifications { get; set; } = true;
    public bool WeeklyReportNotifications { get; set; } = false;
    public bool SoundAlerts { get; set; } = false;

    // Scheduled Scans
    public bool ScheduledScanEnabled { get; set; } = true;
    public string ScanFrequency { get; set; } = "Weekly";
    public string ScanDay { get; set; } = "Monday";
    public string ScanTime { get; set; } = "02:00 AM";
    public string ScheduledScanType { get; set; } = "Quick Scan";

    // Exclusions
    public List<string> ExcludedFiles { get; set; } = [];
    public List<string> ExcludedFolders { get; set; } = [];
}
