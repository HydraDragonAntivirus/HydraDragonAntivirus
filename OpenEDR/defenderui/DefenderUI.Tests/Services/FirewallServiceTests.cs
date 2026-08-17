using System.Threading.Tasks;
using DefenderUI.Services;
using FluentAssertions;
using Xunit;

namespace DefenderUI.Tests.Services;

public class FirewallServiceTests
{
    [Fact]
    public async Task GetActiveFirewallRulesAsync_ReturnsRulesList()
    {
        var service = new FirewallService();
        var rules = await service.GetActiveFirewallRulesAsync();

        rules.Should().NotBeNull();
        rules.Count.Should().BeGreaterThan(0);
    }
}
