namespace Sefer.Backend.Authentication.Lib;

public sealed class TokenAuthenticationHandler : AuthenticationHandler<SchemeOptions>
{
    public const string SchemeName = "header-authentication";

    public const string SessionName = "auth-id";

    private readonly ITokenGenerator _tokenGenerator;

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
        Token? authorizationToken = null;

        if (HasHeader("X-AccessToken")) authorizationToken = _tokenGenerator.Verify(GetHeader("X-AccessToken"));
        else if (HasBearerHeader()) authorizationToken = _tokenGenerator.Verify(GetHeader("Authorization")[7..]);
        else if (HasHeader("Authorization")) authorizationToken = _tokenGenerator.Verify(GetHeader("Authorization"));
        else if (IsQueryStringAuth()) authorizationToken = _tokenGenerator.Verify(Request.Query["access_token"]!);
        else if (HasAuthorizationCookie()) authorizationToken = _tokenGenerator.Verify(Request.Cookies[SessionName]!);

        return authorizationToken;
    }

    private bool HasHeader(string header)
    {
        return Request.Headers.ContainsKey(header);
    }

    private string GetHeader(string header)
    {
        return HasHeader(header) == false ? string.Empty : Request.Headers[header].ToString();
    }

    private bool HasBearerHeader()
    {
        return HasHeader("Authorization") && Request.Headers["Authorization"].ToString().StartsWith("Bearer ");
    }

    private bool HasAuthorizationCookie() =>
            Request.Cookies.ContainsKey(SessionName) &&
            !string.IsNullOrEmpty(Request.Cookies[SessionName]);

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

    private bool IsQueryStringAuth() =>
        Request.Query.ContainsKey("access_token") &&
        !string.IsNullOrEmpty(Request.Query["access_token"]);
}