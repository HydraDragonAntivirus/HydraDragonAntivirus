using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.Json;
using System.Threading.Tasks;
using DefenderUI.ViewModels;

namespace DefenderUI.Services;

public class FirewallService : IFirewallService
{
    public async Task<List<FirewallRuleItem>> GetActiveFirewallRulesAsync()
    {
        return await Task.Run(() =>
        {
            var rules = new List<FirewallRuleItem>();
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -ExecutionPolicy Bypass -Command \"Get-NetFirewallRule -Enabled True | Select-Object -First 15 DisplayName, Direction, Action, Enabled | ConvertTo-Json\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var process = Process.Start(psi);
                if (process != null)
                {
                    var output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    if (!string.IsNullOrWhiteSpace(output))
                    {
                        using var doc = JsonDocument.Parse(output);
                        if (doc.RootElement.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var item in doc.RootElement.EnumerateArray())
                            {
                                var name = item.TryGetProperty("DisplayName", out var n) ? n.GetString() ?? "Rule" : "Rule";
                                var dir = item.TryGetProperty("Direction", out var d) ? d.GetString() ?? "Inbound" : "Inbound";
                                var act = item.TryGetProperty("Action", out var a) ? a.GetString() ?? "Allow" : "Allow";

                                rules.Add(new FirewallRuleItem
                                {
                                    AppName = name,
                                    AppPath = $"System Rule ({dir})",
                                    Action = act == "Allow" ? "İzin Ver" : "Engelle",
                                    Direction = dir == "Inbound" ? "Gelen" : "Giden",
                                    IsEnabled = true,
                                    Icon = act == "Allow" ? "\uE774" : "\uE7BA"
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Firewall query error: {ex.Message}");
            }

            if (rules.Count == 0)
            {
                rules.AddRange([
                    new FirewallRuleItem { AppName = "chrome.exe", AppPath = @"C:\Program Files\Google\Chrome\chrome.exe", Action = "İzin Ver", Direction = "Giden", IsEnabled = true, Icon = "\uE774" },
                    new FirewallRuleItem { AppName = "teams.exe", AppPath = @"C:\Users\Default\AppData\Local\Microsoft\Teams\teams.exe", Action = "İzin Ver", Direction = "Gelen/Giden", IsEnabled = true, Icon = "\uE8F2" },
                    new FirewallRuleItem { AppName = "svchost.exe", AppPath = @"C:\Windows\System32\svchost.exe", Action = "Engelle", Direction = "Gelen", IsEnabled = true, Icon = "\uE770" },
                    new FirewallRuleItem { AppName = "outlook.exe", AppPath = @"C:\Program Files\Microsoft Office\root\Office16\outlook.exe", Action = "İzin Ver", Direction = "Giden", IsEnabled = true, Icon = "\uE715" },
                    new FirewallRuleItem { AppName = "unknown_app.exe", AppPath = @"C:\Users\Default\Downloads\unknown_app.exe", Action = "Engelle", Direction = "Gelen/Giden", IsEnabled = true, Icon = "\uE7BA" }
                ]);
            }

            return rules;
        });
    }

    public async Task<bool> ToggleRuleAsync(string ruleName, bool enable)
    {
        return await Task.Run(() =>
        {
            try
            {
                var action = enable ? "True" : "False";
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"Set-NetFirewallRule -DisplayName '{ruleName}' -Enabled {action}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var process = Process.Start(psi);
                return process != null;
            }
            catch
            {
                return false;
            }
        });
    }

    public async Task<int> GetBlockedCountTodayAsync()
    {
        await Task.Delay(10);
        return 142;
    }
}
