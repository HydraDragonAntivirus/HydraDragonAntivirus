using DefenderUI.Models;

namespace DefenderUI.Services;

public class MockDataService
{
    public ProtectionStatus GetProtectionStatus()
    {
        return new ProtectionStatus
        {
            State = ProtectionState.Protected,
            SecurityScore = 85,
            StatusMessage = "Your device is protected",
            Description = "All security features are active and up to date."
        };
    }

    public List<ThreatInfo> GetRecentThreats()
    {
        return
        [
            new ThreatInfo
            {
                ThreatName = "Trojan:Win32/Emotet.G",
                FilePath = @"C:\Users\Default\Downloads\invoice_2024.exe",
                DetectionDate = DateTime.Now.AddHours(-2),
                RiskLevel = RiskLevel.Critical,
                ActionTaken = "Quarantined",
                IsQuarantined = true
            },
            new ThreatInfo
            {
                ThreatName = "PUA:Win32/Presenoker",
                FilePath = @"C:\Program Files\FreeApp\toolbar.dll",
                DetectionDate = DateTime.Now.AddDays(-1),
                RiskLevel = RiskLevel.Medium,
                ActionTaken = "Blocked",
                IsQuarantined = false
            },
            new ThreatInfo
            {
                ThreatName = "Adware:Win32/BrowserModifier",
                FilePath = @"C:\Users\Default\AppData\Local\Temp\setup.exe",
                DetectionDate = DateTime.Now.AddDays(-3),
                RiskLevel = RiskLevel.Low,
                ActionTaken = "Removed",
                IsQuarantined = false
            },
            new ThreatInfo
            {
                ThreatName = "Ransom:Win32/LockBit.A",
                FilePath = @"C:\Users\Default\Documents\encrypted_file.locked",
                DetectionDate = DateTime.Now.AddDays(-5),
                RiskLevel = RiskLevel.Critical,
                ActionTaken = "Quarantined",
                IsQuarantined = true
            },
            new ThreatInfo
            {
                ThreatName = "Trojan:Win32/AgentTesla.SM",
                FilePath = @"C:\Users\Default\Downloads\report.docx.exe",
                DetectionDate = DateTime.Now.AddDays(-7),
                RiskLevel = RiskLevel.High,
                ActionTaken = "Removed",
                IsQuarantined = false
            }
        ];
    }

    public ScanResult GetLastScanResult()
    {
        return new ScanResult
        {
            Type = ScanType.Quick,
            Status = ScanStatus.Completed,
            StartTime = DateTime.Now.AddHours(-4),
            EndTime = DateTime.Now.AddHours(-4).AddMinutes(12),
            Duration = TimeSpan.FromMinutes(12),
            FilesScanned = 45892,
            ThreatsFound = 2,
            Progress = 100,
            CurrentFile = string.Empty
        };
    }

    public List<ProtectionModule> GetProtectionModules()
    {
        return
        [
            new ProtectionModule
            {
                Name = "Real-time Protection",
                Description = "Monitors your system for threats in real-time",
                Icon = "\uE8BE",
                IsEnabled = true,
                HasIssue = false,
                IssueDescription = string.Empty
            },
            new ProtectionModule
            {
                Name = "Web Protection",
                Description = "Blocks malicious websites and downloads",
                Icon = "\uE774",
                IsEnabled = true,
                HasIssue = false,
                IssueDescription = string.Empty
            },
            new ProtectionModule
            {
                Name = "File Protection",
                Description = "Scans files when accessed or modified",
                Icon = "\uE8B7",
                IsEnabled = true,
                HasIssue = false,
                IssueDescription = string.Empty
            },
            new ProtectionModule
            {
                Name = "Ransomware Protection",
                Description = "Protects your files from encryption attacks",
                Icon = "\uE72E",
                IsEnabled = true,
                HasIssue = false,
                IssueDescription = string.Empty
            },
            new ProtectionModule
            {
                Name = "Email Protection",
                Description = "Scans email attachments for threats",
                Icon = "\uE715",
                IsEnabled = false,
                HasIssue = true,
                IssueDescription = "Email protection is currently disabled"
            },
            new ProtectionModule
            {
                Name = "Network Protection",
                Description = "Monitors network traffic for suspicious activity",
                Icon = "\uE968",
                IsEnabled = true,
                HasIssue = false,
                IssueDescription = string.Empty
            }
        ];
    }

    public List<ActivityLogItem> GetRecentActivity()
    {
        return
        [
            new ActivityLogItem
            {
                Type = ActivityType.ThreatBlocked,
                Title = "Threat blocked",
                Description = "Trojan:Win32/Emotet.G was quarantined",
                Timestamp = DateTime.Now.AddHours(-2)
            },
            new ActivityLogItem
            {
                Type = ActivityType.ScanCompleted,
                Title = "Quick scan completed",
                Description = "45,892 files scanned, 2 threats found",
                Timestamp = DateTime.Now.AddHours(-4)
            },
            new ActivityLogItem
            {
                Type = ActivityType.DatabaseUpdated,
                Title = "Virus definitions updated",
                Description = "Updated to version 1.405.651.0",
                Timestamp = DateTime.Now.AddHours(-6)
            },
            new ActivityLogItem
            {
                Type = ActivityType.FileQuarantined,
                Title = "File quarantined",
                Description = "PUA:Win32/Presenoker moved to quarantine",
                Timestamp = DateTime.Now.AddDays(-1)
            },
            new ActivityLogItem
            {
                Type = ActivityType.ProtectionEnabled,
                Title = "Protection enabled",
                Description = "Real-time protection was turned on",
                Timestamp = DateTime.Now.AddDays(-1).AddHours(-3)
            },
            new ActivityLogItem
            {
                Type = ActivityType.Warning,
                Title = "Email protection disabled",
                Description = "Email protection module is not active",
                Timestamp = DateTime.Now.AddDays(-2)
            },
            new ActivityLogItem
            {
                Type = ActivityType.ScanCompleted,
                Title = "Full scan completed",
                Description = "1,245,678 files scanned, 0 threats found",
                Timestamp = DateTime.Now.AddDays(-3)
            },
            new ActivityLogItem
            {
                Type = ActivityType.ThreatBlocked,
                Title = "Ransomware blocked",
                Description = "Ransom:Win32/LockBit.A was blocked and quarantined",
                Timestamp = DateTime.Now.AddDays(-5)
            },
            new ActivityLogItem
            {
                Type = ActivityType.DatabaseUpdated,
                Title = "Virus definitions updated",
                Description = "Updated to version 1.405.620.0",
                Timestamp = DateTime.Now.AddDays(-6)
            },
            new ActivityLogItem
            {
                Type = ActivityType.ProtectionDisabled,
                Title = "Web protection temporarily disabled",
                Description = "User disabled web protection for 1 hour",
                Timestamp = DateTime.Now.AddDays(-7)
            }
        ];
    }

    public UpdateInfo GetUpdateInfo()
    {
        return new UpdateInfo
        {
            VirusDefinitionVersion = "1.405.651.0",
            AppVersion = "1.0.0",
            LastUpdateDate = DateTime.Now.AddHours(-6),
            IsUpdateAvailable = false,
            UpdateProgress = 0,
            UpdateSize = "45.2 MB"
        };
    }

    public SystemHealthInfo GetSystemHealthInfo()
    {
        return new SystemHealthInfo
        {
            HealthScore = 85,
            CpuImpact = 2.3,
            MemoryUsage = 128.5,
            BackgroundProtection = true,
            AutoUpdates = true,
            SecureBrowser = true,
            SafeNetwork = false
        };
    }

    public List<ThreatInfo> GetQuarantinedItems()
    {
        return
        [
            new ThreatInfo
            {
                ThreatName = "Trojan.Gen.2",
                FilePath = @"C:\Users\John\Downloads\setup_crack.exe",
                DetectionDate = DateTime.Now.AddDays(-1),
                RiskLevel = RiskLevel.Critical,
                ActionTaken = "Quarantined",
                IsQuarantined = true
            },
            new ThreatInfo
            {
                ThreatName = "PUP.Optional.BrowserHelper",
                FilePath = @"C:\Program Files\BrowserHelper\helper.dll",
                DetectionDate = DateTime.Now.AddDays(-2),
                RiskLevel = RiskLevel.Medium,
                ActionTaken = "Quarantined",
                IsQuarantined = true
            },
            new ThreatInfo
            {
                ThreatName = "Adware.Elex.ShrtCln",
                FilePath = @"C:\Users\John\AppData\Local\Temp\cleaner.exe",
                DetectionDate = DateTime.Now.AddDays(-3),
                RiskLevel = RiskLevel.Low,
                ActionTaken = "Quarantined",
                IsQuarantined = true
            },
            new ThreatInfo
            {
                ThreatName = "Backdoor.Agent.FOX",
                FilePath = @"C:\Windows\Temp\svchost_update.exe",
                DetectionDate = DateTime.Now.AddHours(-6),
                RiskLevel = RiskLevel.Critical,
                ActionTaken = "Quarantined",
                IsQuarantined = true
            },
            new ThreatInfo
            {
                ThreatName = "Ransomware.WannaCry.B",
                FilePath = @"C:\Users\John\Documents\invoice.pdf.exe",
                DetectionDate = DateTime.Now.AddDays(-5),
                RiskLevel = RiskLevel.Critical,
                ActionTaken = "Quarantined",
                IsQuarantined = true
            },
            new ThreatInfo
            {
                ThreatName = "Spyware.Keylogger.AX",
                FilePath = @"C:\Program Files (x86)\KeyCapture\logger.sys",
                DetectionDate = DateTime.Now.AddDays(-4),
                RiskLevel = RiskLevel.High,
                ActionTaken = "Quarantined",
                IsQuarantined = true
            },
            new ThreatInfo
            {
                ThreatName = "PUP.Optional.InstallCore",
                FilePath = @"C:\Users\John\Downloads\free_software_bundle.exe",
                DetectionDate = DateTime.Now.AddDays(-7),
                RiskLevel = RiskLevel.Medium,
                ActionTaken = "Quarantined",
                IsQuarantined = true
            },
            new ThreatInfo
            {
                ThreatName = "Trojan.Downloader.Small",
                FilePath = @"C:\Users\John\Desktop\game_patch.exe",
                DetectionDate = DateTime.Now.AddDays(-1),
                RiskLevel = RiskLevel.High,
                ActionTaken = "Quarantined",
                IsQuarantined = true
            }
        ];
    }

    public List<FeatureTileData> GetFeatureTiles()
    {
        return
        [
            new FeatureTileData(
                Glyph: "\uE773",
                Title: "Hızlı Tarama",
                Description: "Kritik alanları saniyeler içinde kontrol edin.",
                BadgeText: null,
                NavigateKey: "scan"),
            new FeatureTileData(
                Glyph: "\uE72E",
                Title: "Tam Sistem Taraması",
                Description: "Tüm diskinizi kapsamlı olarak analiz edin.",
                BadgeText: null,
                NavigateKey: "scan"),
            new FeatureTileData(
                Glyph: "\uE895",
                Title: "Veritabanını Güncelle",
                Description: "Virüs tanımlarını en son sürüme alın.",
                BadgeText: "Yeni",
                NavigateKey: "update"),
            new FeatureTileData(
                Glyph: "\uE7B8",
                Title: "Karantina",
                Description: "İzole edilen tehditleri yönetin.",
                BadgeText: null,
                NavigateKey: "quarantine"),
            new FeatureTileData(
                Glyph: "\uE9D2",
                Title: "Raporlar",
                Description: "Güvenlik olaylarının geçmişini inceleyin.",
                BadgeText: null,
                NavigateKey: "reports"),
            new FeatureTileData(
                Glyph: "\uE72E",
                Title: "Gizlilik Koruması",
                Description: "Tarayıcı ve kimlik güvenliğini ayarlayın.",
                BadgeText: null,
                NavigateKey: "protection"),
        ];
    }

    public List<ScanModeOption> GetScanModeOptions()
    {
        return
        [
            new ScanModeOption(
                Mode: ScanMode.Quick,
                Glyph: "\uE773",
                Title: "Hızlı Tarama",
                Description: "En yaygın enfeksiyon noktaları (belirli klasör + bellek) kontrol edilir.",
                EstimatedDuration: "~1-2 dk"),
            new ScanModeOption(
                Mode: ScanMode.Full,
                Glyph: "\uE72E",
                Title: "Tam Sistem",
                Description: "Tüm dosyalar ve klasörler derinlemesine taranır.",
                EstimatedDuration: "~30-60 dk"),
            new ScanModeOption(
                Mode: ScanMode.Custom,
                Glyph: "\uE8B7",
                Title: "Özel Tarama",
                Description: "Seçtiğiniz klasörleri tarayın.",
                EstimatedDuration: "değişken"),
            new ScanModeOption(
                Mode: ScanMode.Removable,
                Glyph: "\uE88E",
                Title: "Çıkarılabilir",
                Description: "USB bellek, harici disk ve optik sürücüler taranır.",
                EstimatedDuration: "~5-10 dk"),
        ];
    }

    public List<ScanResult> GetScanHistory()
    {
        return
        [
            new ScanResult
            {
                Type = ScanType.Quick,
                Status = ScanStatus.Completed,
                StartTime = DateTime.Now.AddDays(-1),
                EndTime = DateTime.Now.AddDays(-1).AddMinutes(2).AddSeconds(5),
                Duration = TimeSpan.FromMinutes(2).Add(TimeSpan.FromSeconds(5)),
                FilesScanned = 12847,
                ThreatsFound = 0,
                Progress = 100
            },
            new ScanResult
            {
                Type = ScanType.Full,
                Status = ScanStatus.Completed,
                StartTime = DateTime.Now.AddDays(-3),
                EndTime = DateTime.Now.AddDays(-3).AddMinutes(45).AddSeconds(12),
                Duration = TimeSpan.FromMinutes(45).Add(TimeSpan.FromSeconds(12)),
                FilesScanned = 234591,
                ThreatsFound = 1,
                Progress = 100
            },
            new ScanResult
            {
                Type = ScanType.Quick,
                Status = ScanStatus.Completed,
                StartTime = DateTime.Now.AddDays(-4),
                EndTime = DateTime.Now.AddDays(-4).AddMinutes(1).AddSeconds(58),
                Duration = TimeSpan.FromMinutes(1).Add(TimeSpan.FromSeconds(58)),
                FilesScanned = 12503,
                ThreatsFound = 0,
                Progress = 100
            },
            new ScanResult
            {
                Type = ScanType.Custom,
                Status = ScanStatus.Completed,
                StartTime = DateTime.Now.AddDays(-6),
                EndTime = DateTime.Now.AddDays(-6).AddMinutes(12).AddSeconds(30),
                Duration = TimeSpan.FromMinutes(12).Add(TimeSpan.FromSeconds(30)),
                FilesScanned = 45220,
                ThreatsFound = 0,
                Progress = 100
            }
        ];
    }
}