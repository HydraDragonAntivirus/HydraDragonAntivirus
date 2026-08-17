using DefenderUI.Helpers;
using FluentAssertions;
using Xunit;

namespace DefenderUI.Tests.Helpers;

public class CryptoHelperTests
{
    [Fact]
    public void ComputeSha256_ReturnsValid64CharHex_ForAnyStringOrPath()
    {
        var hash = CryptoHelper.ComputeSha256("test_sample.exe");
        hash.Should().NotBeNullOrEmpty();
        hash.Length.Should().Be(64);
    }
}
