using System.Threading.Tasks;
using DefenderUI.Models;

namespace DefenderUI.Services;

public interface IWindowsDefenderService
{
    Task<ProtectionStatus> GetLiveProtectionStatusAsync();
    Task<bool> IsRealTimeProtectionEnabledAsync();
    Task<string> GetAntivirusSignatureVersionAsync();
    Task<bool> TriggerQuickScanAsync();
}
