namespace Sefer.Backend.Authentication.Lib.Tests;

[TestClass]
public class TokenGeneratorTests
{
    [TestMethod]
    public void Encrypt_IsGenerated()
    {
        // Arrange
        var generator = Util.Mocks.GetGenerator();
        var expiration = DateTime.UtcNow;

        // Act
        var token = generator.CreateToken(17, "Admin", expiration);

        // Assert
        token.Should().NotBeEmpty();
        token.Should().Contain(".");
    }

    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("this_is_not_a_token")]
    public void Verify_IncorrectToken(string token)
    {
        // Arrange
        var generator = Util.Mocks.GetGenerator();
        
        // Act
        var verify = generator.Verify(token);
        
        // Assert
        verify.Should().BeNull();
    }
    
    [TestMethod]
    public void Verify_InCorrectHash()
    {
        // Arrange
        const string token = "eyJTZXNzaW9uSWQiOiJlYmE2MmM0Yi0wMGM4LTRlMzQtOGJkNi02ZDljMWFhZjQ2ODciLCJVc2VySWQiOjE3LCJVc2VyUm9sZSI6IkFkbWluIiwiRXhwaXJhdGlvbkRhdGVUaW1lIjoiMjAyMi0wMy0yMFQwOTo1NTozOS43MjkyNDlaIn0=.WySOOeWneiCgTgbUt250tlOZRrZIxJaM/XZyWkvCJ9g8wnvUsyg828YIzCWoJpYj";
        var generator = Util.Mocks.GetGenerator();
        
        // Act
        var verify = generator.Verify(token);
        
        // Assert
        verify.Should().BeNull();
    }

    [TestMethod]
    public void Verify_ExpiredToken()
    {
        const string token = "eyJTZXNzaW9uSWQiOiI1ODY2OWQ3Mi1hZmUxLTQ1N2ItYTJiMy04MDkwZjVmNmQ5OGEiLCJVc2VySWQiOjE3LCJVc2VyUm9sZSI6IkFkbWluIiwiRXhwaXJhdGlvbkRhdGVUaW1lIjoiMjAyMi0wMy0xOVQwOTo1OTo0MC40MDA5NzRaIn0=.O6TL5rikTAYQtc0piPvk5Tj41OelJHqNAwhgp3fs67pnh13DXlTNNXpkJaf7bulq";
        var generator = Util.Mocks.GetGenerator();
        
        // Act
        var verify = generator.Verify(token);
        
        // Assert
        verify.Should().BeNull();
    }

    [TestMethod]
    public void Encrypt_And_Verify()
    {
        // Arrange
        var generator = Util.Mocks.GetGenerator();
        var expiration = DateTime.UtcNow.AddDays(1);
        var token = generator.CreateToken(17, "Admin", expiration);
        
        // Act
        var verify = generator.Verify(token);
        
        // Assert
        verify.Should().NotBeNull();
        verify?.UserId.Should().Be(17);
        verify?.UserRole.Should().Be("Admin");
        verify?.SessionId.Should().NotBe(Guid.Empty);
    }
}