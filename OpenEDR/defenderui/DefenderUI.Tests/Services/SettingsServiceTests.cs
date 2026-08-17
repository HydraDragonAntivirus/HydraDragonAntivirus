using System.IO;
using DefenderUI.Services;
using FluentAssertions;
using Xunit;

namespace DefenderUI.Tests.Services;

public class SettingsServiceTests
{
    [Fact]
    public void SettingsService_SavesAndLoads_Successfully()
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"test_settings_{System.Guid.NewGuid()}.json");

        try
        {
            var service1 = new SettingsService(tempFile);
            service1.UpdateSettings(s =>
            {
                s.SelectedLanguage = "English";
                s.UseRealDefenderEngine = true;
                s.ReduceMotion = true;
            });

            var service2 = new SettingsService(tempFile);
            service2.CurrentSettings.SelectedLanguage.Should().Be("English");
            service2.CurrentSettings.UseRealDefenderEngine.Should().BeTrue();
            service2.CurrentSettings.ReduceMotion.Should().BeTrue();
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }
}
