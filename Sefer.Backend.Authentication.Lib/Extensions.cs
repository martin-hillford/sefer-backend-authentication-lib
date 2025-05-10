namespace Sefer.Backend.Authentication.Lib;

public static class Extensions
{
    /// <summary>
    /// This add the default token authentication to the service collection.
    /// The default authentication uses the default token provider that is using
    /// the network config based configuration. This must be added seperatly!
    /// </summary>
    public static IServiceCollection AddTokenAuthentication(this IServiceCollection services) => AddTokenAuthentication<KeyProvider>(services);

    /// <summary>
    /// Adds the token authentication to the service collection given a keyprovider using generics
    /// </summary>
    public static IServiceCollection AddTokenAuthentication<T>(this IServiceCollection services) where T : class, IKeyProvider
    {
        services.AddSingleton<IKeyProvider, T>();
        return AddTokenAuthenticationToServiceCollection(services);
    }

    /// <summary>
    /// Adds the token authentication to the service collection given a keyprovider
    /// </summary>
    public static IServiceCollection AddTokenAuthentication(this IServiceCollection services, IKeyProvider provider)
    {
        services.AddSingleton(provider);
        return AddTokenAuthenticationToServiceCollection(services);
    }

    private static IServiceCollection AddTokenAuthenticationToServiceCollection(IServiceCollection services)
    {
        var policy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .AddAuthenticationSchemes(TokenAuthenticationHandler.SchemeName)
            .Build();

        services.AddSingleton<ITokenGenerator, TokenGenerator>();
        services.AddAuthorizationBuilder().SetDefaultPolicy(policy);

        services
            .AddAuthentication(options =>
            {
                options.DefaultScheme = TokenAuthenticationHandler.SchemeName;
                options.DefaultAuthenticateScheme = TokenAuthenticationHandler.SchemeName;
                options.DefaultChallengeScheme = TokenAuthenticationHandler.SchemeName;
            })
            .AddScheme<SchemeOptions, TokenAuthenticationHandler>(TokenAuthenticationHandler.SchemeName, _ => { });

        return services;
    }

    public static WebApplicationBuilder AddSwaggerWithToken(this WebApplicationBuilder builder)
    {
        builder.Services.AddSwaggerWithToken();
        return builder;
    }

    public static IServiceCollection AddSwaggerWithToken(this IServiceCollection services)
    {
        var securityScheme = new OpenApiSecurityScheme()
        {
            Name = "Authorization",
            Type = SecuritySchemeType.ApiKey,
            Scheme = "Bearer",
            BearerFormat = "JWT",
            In = ParameterLocation.Header,
            Description = "Authorization Token based security"
        };

        var securityReq = new OpenApiSecurityRequirement
        {
            {
                new OpenApiSecurityScheme
                {
                    Reference = new OpenApiReference
                    {
                        Type = ReferenceType.SecurityScheme,
                        Id = "Bearer"
                    }
                },
                Array.Empty<string>()
            }
        };

        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(o =>
        {
            o.AddSecurityDefinition("Bearer", securityScheme);
            o.AddSecurityRequirement(securityReq);
        });

        return services;
    }

    public static WebApplication UseSwaggerWithToken(this WebApplication app)
    {
        if (!app.Environment.IsDevelopment()) return app;

        app.UseSwagger();
        app.UseSwaggerUI(c =>
        {
            c.DefaultModelsExpandDepth(-1);
            c.EnableTryItOutByDefault();
        });

        return app;
    }

    public static IApplicationBuilder UseSwaggerWithToken(this IApplicationBuilder app)
    {
        app.UseSwagger();
        app.UseSwaggerUI(c =>
        {
            c.DefaultModelsExpandDepth(-1);
            c.EnableTryItOutByDefault();
        });

        return app;
    }
}