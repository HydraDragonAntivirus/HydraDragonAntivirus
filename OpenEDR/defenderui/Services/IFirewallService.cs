using System.Collections.Generic;
using System.Threading.Tasks;
using DefenderUI.ViewModels;

namespace DefenderUI.Services;

public interface IFirewallService
{
    Task<List<FirewallRuleItem>> GetActiveFirewallRulesAsync();
    Task<bool> ToggleRuleAsync(string ruleName, bool enable);
    Task<int> GetBlockedCountTodayAsync();
}
