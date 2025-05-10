namespace Sefer.Backend.Authentication.Lib.Tests;

[TestClass]
public class TokenTests
{
    [TestMethod]
    public void UniqueId_CorrectGeneration()
    {
        // Arrange
        var sessionId = Guid.NewGuid();
        var now = DateTime.UtcNow;

        var token = new Token
        {
            ExpirationDateTime = now,
            SessionId = sessionId,
            UserId = 17,
            UserRole = "Admin"
        };

        // Act
        var uniqueId = token.UniqueId;

        // Assert
        var expected = sessionId + "17Admin" + now.ToString("yyyyMMddhhmm");
        uniqueId.Should().Be(expected);
    }
}