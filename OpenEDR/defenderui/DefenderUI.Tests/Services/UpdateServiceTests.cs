using System.Threading.Tasks;
using DefenderUI.Services;
using FluentAssertions;
using Xunit;

namespace DefenderUI.Tests.Services;

public class UpdateServiceTests
{
    [Fact]
    public async Task DownloadAndInstallUpdateAsync_ReportsProgress()
    {
        var service = new UpdateService();
        int maxProgress = 0;

        var success = await service.DownloadAndInstallUpdateAsync(args =>
        {
            if (args.ProgressPercent > maxProgress)
            {
                maxProgress = args.ProgressPercent;
            }
        });

        success.Should().BeTrue();
        maxProgress.Should().Be(100);
    }
}
