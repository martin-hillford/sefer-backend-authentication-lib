namespace Sefer.Backend.Authentication.Lib;

public sealed class TokenAuthenticationHandler : AuthenticationHandler<SchemeOptions>
{
    public const string SchemeName = "header-authentication";

    public const string SessionName = "auth-id";

    private readonly ITokenGenerator _tokenGenerator;

    [SuppressMessage("ReSharper", "ConvertToPrimaryConstructor")]
    public TokenAuthenticationHandler
    (
        IOptionsMonitor<SchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ITokenGenerator tokenGenerator
    ) : base(options, logger, encoder)
    {
        _tokenGenerator = tokenGenerator;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var token = GetAuthorizationTokenFromRequest();
        if (token == null) return Fail();

        var ticket = CreateTicket(token);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    private Token? GetAuthorizationTokenFromRequest()
    {
        var provider = new TokenAuthenticationProvider(Request, _tokenGenerator);
        return provider.GetAuthorizationTokenFromRequest();
    }

    private static Task<AuthenticateResult> Fail()
    {
        var result = AuthenticateResult.Fail("No Access Token in header");
        return Task.FromResult(result);
    }

    private AuthenticationTicket CreateTicket(Token token)
    {
        var claims = new[] {
            new Claim(ClaimTypes.NameIdentifier, token.UserId.ToString()),
            new Claim(ClaimTypes.Role, token.UserRole)
        };

        var claimsIdentity = new ClaimsIdentity(claims, nameof(TokenAuthenticationHandler));
        return new AuthenticationTicket(new ClaimsPrincipal(claimsIdentity), Scheme.Name);
    }
}