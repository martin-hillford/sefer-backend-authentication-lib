namespace Sefer.Backend.Authentication.Lib;

public class TokenAuthenticationProvider(HttpRequest request, ITokenGenerator tokenGenerator)
{
    private const string SessionName = "auth-id";
    
    public bool IsAuthenticated() => GetAuthorizationTokenFromRequest() != null;

    public bool IsAuthenticated(string role)
    {
        var token = GetAuthorizationTokenFromRequest();
        return token?.UserRole == role;
    }
    
    public Token? GetAuthorizationTokenFromRequest()
    {
        Token? authorizationToken = null;

        if (HasHeader("X-AccessToken")) authorizationToken = tokenGenerator.Verify(GetHeader("X-AccessToken"));
        else if (HasBearerHeader()) authorizationToken = tokenGenerator.Verify(GetHeader("Authorization")[7..]);
        else if (HasHeader("Authorization")) authorizationToken = tokenGenerator.Verify(GetHeader("Authorization"));
        else if (IsQueryStringAuth()) authorizationToken = tokenGenerator.Verify(request.Query["access_token"]!);
        else if (HasAuthorizationCookie()) authorizationToken = tokenGenerator.Verify(request.Cookies[SessionName]!);

        return authorizationToken;
    }
    
    private bool HasHeader(string header) => request.Headers.ContainsKey(header);

    private string GetHeader(string header)
    {
        return HasHeader(header) == false ? string.Empty : request.Headers[header].ToString();
    }

    private bool HasBearerHeader()
    {
        return HasHeader("Authorization") && request.Headers.Authorization.ToString().StartsWith("Bearer ");
    }

    private bool HasAuthorizationCookie() =>
        request.Cookies.ContainsKey(SessionName) &&
        !string.IsNullOrEmpty(request.Cookies[SessionName]);
    
    private bool IsQueryStringAuth() =>
        request.Query.ContainsKey("access_token") &&
        !string.IsNullOrEmpty(request.Query["access_token"]);
}