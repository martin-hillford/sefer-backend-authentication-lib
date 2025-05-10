namespace Sefer.Backend.Authentication.Lib;

public class CookieMiddleware(RequestDelegate next)
{
    public Task Invoke(HttpContext context, ITokenGenerator tokenGenerator, IOptions<ISecurityOptions> securityOptions)
    {
        var options = securityOptions?.Value;

        if (options == null) return next(context);

        var cookieService = new AuthCookieService(tokenGenerator, context, options);
        var expiration = DateTime.UtcNow.AddHours(options.TokenDurationInt);
        cookieService.ExtendAuthCookie(expiration);
        return next(context);
    }
}