using DefenderUI.Services;
using FluentAssertions;
using Xunit;

namespace DefenderUI.Tests.Services;

public class LocalizationServiceTests
{
    [Fact]
    public void GetString_ReturnsTurkishValue_WhenTurkishSelected()
    {
        var service = new LocalizationService();
        service.SetLanguage("Türkçe");

        var title = service.GetString("Dashboard_Title");
        title.Should().Be("Kontrol Paneli");
    }

    [Fact]
    public void GetString_ReturnsEnglishValue_WhenEnglishSelected()
    {
        var service = new LocalizationService();
        service.SetLanguage("English");

        var title = service.GetString("Dashboard_Title");
        title.Should().Be("Dashboard");
    }

    [Fact]
    public void SetLanguage_TriggersLanguageChangedEvent()
    {
        var service = new LocalizationService();
        bool eventFired = false;
        service.LanguageChanged += (s, e) => eventFired = true;

        service.SetLanguage("English");
        eventFired.Should().BeTrue();
    }
}
