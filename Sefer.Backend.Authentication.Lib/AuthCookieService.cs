namespace Sefer.Backend.Authentication.Lib;

public class AuthCookieService(ITokenGenerator tokenGenerator, HttpContext httpContext, ISecurityOptions securityOptions)
{
    private IResponseCookies? Cookies => httpContext?.Response.Cookies;

    private static string CookieName => TokenAuthenticationHandler.SessionName;

    public void AppendAuthCookie(int userId, string userRole, DateTime expiration)
    {
        if (httpContext == null) return;

        var token = tokenGenerator.CreateToken(userId, userRole, expiration);
        AppendAuthCookie(token, expiration);
    }

    private void AppendAuthCookie(string token, DateTime expiration)
    {
        if (Cookies == null) return;
        var options = new CookieOptions()
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Strict,
            Expires = expiration,
            Secure = securityOptions.SecureCookie,
            Path = "/"
        };
        Cookies.Append(CookieName, token, options);
    }

    public void RemoveAuthCookie()
    {
        if (Cookies == null) return;
        Cookies.Delete(CookieName);
    }

    public void ExtendAuthCookie(DateTime expiration)
    {
        var requestCookies = httpContext?.Request.Cookies;
        if (requestCookies == null) return;
        if (!requestCookies.ContainsKey(CookieName)) return;
        if (string.IsNullOrEmpty(requestCookies[CookieName])) return;

        AppendAuthCookie(requestCookies[CookieName]!, expiration);
    }
}
