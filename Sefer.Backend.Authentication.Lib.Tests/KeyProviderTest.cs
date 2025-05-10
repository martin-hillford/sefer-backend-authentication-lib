namespace Sefer.Backend.Authentication.Lib.Tests;

[TestClass]
public class KeyProviderTest
{
    [TestMethod]
    public void GetKey_ReturnsValue()
    {
        // Arrange
        var configuration = new Mock<IConfiguration>();
        var section = new Mock<IConfigurationSection>();
        section.Setup(s => s.Value).Returns("Key");
        configuration.Setup(c => c.GetSection("SharedKey")).Returns(section.Object);

        var provider = new KeyProvider(configuration.Object);

        // Act
        var key = provider.GetKey();

        // Assert
        key.Should().Be("Key");
    }
}