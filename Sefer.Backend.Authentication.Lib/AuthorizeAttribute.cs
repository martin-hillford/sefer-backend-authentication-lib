namespace Sefer.Backend.Authentication.Lib;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public class AuthorizeAttribute : Microsoft.AspNetCore.Authorization.AuthorizeAttribute
{
    public AuthorizeAttribute()
    {
        AuthenticationSchemes = TokenAuthenticationHandler.SchemeName;
    }
}

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public class AllowAnonymousAttribute : Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute
{
    
}