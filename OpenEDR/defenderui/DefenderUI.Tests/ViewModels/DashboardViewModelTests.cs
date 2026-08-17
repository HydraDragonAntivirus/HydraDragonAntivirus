using System.Threading.Tasks;
using DefenderUI.Models;
using DefenderUI.Services;
using DefenderUI.ViewModels;
using FluentAssertions;
using Moq;
using Xunit;

namespace DefenderUI.Tests.ViewModels;

public class DashboardViewModelTests
{
    [Fact]
    public void LoadData_UsesMockDataService_WhenRealEngineDisabled()
    {
        var mockData = new MockDataService();
        var vm = new DashboardViewModel(mockData);

        vm.SecurityScore.Should().Be(85);
        vm.StatusMessage.Should().Be("Your device is protected");
    }

    [Fact]
    public async Task LoadData_UsesDefenderService_WhenRealEngineEnabled()
    {
        var mockData = new MockDataService();
        var mockSettings = new Mock<ISettingsService>();
        mockSettings.Setup(s => s.CurrentSettings).Returns(new AppSettings { UseRealDefenderEngine = true });

        var mockDefender = new Mock<IWindowsDefenderService>();
        mockDefender.Setup(d => d.GetLiveProtectionStatusAsync())
                    .ReturnsAsync(new ProtectionStatus
                    {
                        State = ProtectionState.Protected,
                        SecurityScore = 98,
                        StatusMessage = "Live Windows Defender Active",
                        Description = "All systems operational"
                    });
        mockDefender.Setup(d => d.GetAntivirusSignatureVersionAsync())
                    .ReturnsAsync("1.403.9999.0");

        var vm = new DashboardViewModel(mockData, null, mockDefender.Object, mockSettings.Object);

        // Allow async LoadData to run
        await Task.Delay(100);

        vm.SecurityScore.Should().Be(98);
        vm.StatusMessage.Should().Be("Live Windows Defender Active");
    }
}
