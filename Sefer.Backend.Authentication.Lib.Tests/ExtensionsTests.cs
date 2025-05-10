namespace Sefer.Backend.Authentication.Lib.Tests;

[TestClass]
public class ExtensionsTests
{
    [TestMethod]
    public void AddTokenAuthentication_IServiceCollection()
    {
        // Arrange
        var services = new Mock<IServiceCollection>();

        // Act
        services.Object.AddTokenAuthentication<KeyProvider>();

        // Assert
        services.VerifyAddSingleTon<IKeyProvider, KeyProvider>();
        services.VerifyAddSingleTon<ITokenGenerator, TokenGenerator>();
    }

    [TestMethod]
    public void AddTokenAuthentication_IServiceCollection_KeyProvider()
    {
        // Arrange
        var services = new Mock<IServiceCollection>();
        var configuration = new Mock<IConfiguration>();

        // Act
        services.Object.AddTokenAuthentication(new KeyProvider(configuration.Object));

        // Assert
        services.VerifyAddSingleTon<ITokenGenerator, TokenGenerator>();
    }

    [TestMethod]
    public void AddSwaggerWithToken_IServiceCollection()
    {
        // Arrange
        var services = new Mock<IServiceCollection>();

        // Act
        services.Object.AddSwaggerWithToken();
    }
}

