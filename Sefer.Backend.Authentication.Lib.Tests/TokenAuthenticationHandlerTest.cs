namespace Sefer.Backend.Authentication.Lib.Tests;

[TestClass]
public class TokenAuthenticationHandlerTest
{
    #region tests

    [TestMethod]
    public async Task HandleAuthenticateAsync_NoAuthorizationHeader_Fail()
    {
        // Arrange
        var context = new DefaultHttpContext();
        var generator = new Mock<ITokenGenerator>();
        var handler = await CreateHandler(context, generator);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        result.Should().NotBeNull();
        result.Succeeded.Should().BeFalse();
        result.Failure?.Message.Should().Be("No Access Token in header");
    }

    [TestMethod]
    [DataRow("X-AccessToken")]
    [DataRow("x-accessToken")]
    [DataRow("Authorization")]
    public async Task HandleAuthenticateAsync_TokenInHeader_Success(string header)
    {
        // Arrange
        var context = CreateContext(header, "token");
        var handler = await CreateHandler(context);

        // Assert
        var result = await handler.AuthenticateAsync();

        // Assert
        result.Should().NotBeNull();
        result.Succeeded.Should().BeTrue();
    }

    [TestMethod]
    public async Task HandleAuthenticateAsync_BearerToken_Success()
    {
        // Arrange
        var context = CreateContext("Authorization", "Bearer token");
        var handler = await CreateHandler(context);

        // Assert
        var result = await handler.AuthenticateAsync();

        // Assert
        result.Should().NotBeNull();
        result.Succeeded.Should().BeTrue();
    }

    [TestMethod]
    public async Task HandleAuthenticateAsync_Cookie_Success()
    {
        // Arrange
        var token = "token-some-id-12312";
        var cookie = new KeyValuePair<string, string>(TokenAuthenticationHandler.SessionName, token);
        var cookies = new CookieCollection() { cookie };
        var request = new Mock<HttpRequest>();
        var headers = new HeaderDictionary { };
        var context = new Mock<HttpContext>();
        var query = new QueryCollection();

        request.Setup(r => r.Cookies).Returns(cookies);
        request.Setup(r => r.Headers).Returns(headers);
        request.Setup(r => r.Query).Returns(query);
        context.Setup(c => c.Request).Returns(request.Object);

        var handler = await CreateHandler(context.Object, token);

        // Assert
        var result = await handler.AuthenticateAsync();

        // Assert
        result.Should().NotBeNull();
        result.Succeeded.Should().BeTrue();
    }

    [TestMethod]
    public async Task HandleAuthenticateAsync_QueryString_Success()
    {
        // Arrange
        var context = CreateContextWithQuery("access_token", "token");
        var handler = await CreateHandler(context);

        // Assert
        var result = await handler.AuthenticateAsync();

        // Assert
        result.Should().NotBeNull();
        result.Succeeded.Should().BeTrue();
    }

    [TestMethod]
    [DataRow("enter", "token")]
    [DataRow("access_token", "no-access")]
    public async Task HandleAuthenticateAsync_QueryString_Failed(string key, string value)
    {
        // Arrange
        var context = CreateContextWithQuery(key, value);
        var handler = await CreateHandler(context);

        // Assert
        var result = await handler.AuthenticateAsync();

        // Assert
        result.Should().NotBeNull();
        result.Succeeded.Should().BeFalse();
    }

    #endregion

    #region helpers

    private static HttpContext CreateContext(string header, string value)
    {
        var headers = new HeaderDictionary { { header, value } };

        var request = new Mock<HttpRequest>();
        request.Setup(r => r.Headers).Returns(headers);

        var context = new Mock<HttpContext>();
        context.Setup(c => c.Request).Returns(request.Object);
        return context.Object;
    }

    private static DefaultHttpContext CreateContextWithQuery(string key, string value)
    {
        return new DefaultHttpContext
        {
            Request = { QueryString = new QueryString($"?{key}={value}") }
        };
    }

    private static async Task<TokenAuthenticationHandler> CreateHandler(HttpContext context, string token = "token")
    {
        var data = new Token { UserId = 1, UserRole = "Admin" };
        var generator = new Mock<ITokenGenerator>();
        generator.Setup(g => g.Verify(token)).Returns(data);
        return await CreateHandler(context, generator);
    }

    private static async Task<TokenAuthenticationHandler> CreateHandler(HttpContext context, IMock<ITokenGenerator> generator)
    {
        var options = new Mock<IOptionsMonitor<SchemeOptions>>();

        options
            .Setup(x => x.Get(It.IsAny<string>()))
            .Returns(new SchemeOptions());

        var logger = new Mock<ILogger<TokenAuthenticationHandler>>();
        var loggerFactory = new Mock<ILoggerFactory>();
        loggerFactory.Setup(x => x.CreateLogger(It.IsAny<String>())).Returns(logger.Object);

        var encoder = new Mock<UrlEncoder>();

        var handler = new TokenAuthenticationHandler(options.Object, loggerFactory.Object, encoder.Object, generator.Object);
        await handler.InitializeAsync(new AuthenticationScheme(TokenAuthenticationHandler.SchemeName, null, typeof(TokenAuthenticationHandler)), context);

        return handler;
    }

    #endregion
}