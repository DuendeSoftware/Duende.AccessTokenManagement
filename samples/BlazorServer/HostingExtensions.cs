using BlazorServer.Plumbing;
using BlazorServer.Services;
using Duende.TokenManagement.OpenIdConnect;
using Serilog;

namespace BlazorServer;

public static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddTransient<CookieEvents>();
        builder.Services.AddTransient<OidcEvents>();
        
        builder.Services.AddAuthentication(options =>
            {
                options.DefaultScheme = "cookie";
                options.DefaultChallengeScheme = "oidc";
                options.DefaultSignOutScheme = "oidc";
            })
            .AddCookie("cookie", options =>
            {
                options.Cookie.Name = "__Host-blazor";
                options.Cookie.SameSite = SameSiteMode.Lax;

                options.EventsType = typeof(CookieEvents);
            })
            .AddOpenIdConnect("oidc", options =>
            {
                options.Authority = "https://demo.duendesoftware.com";

                // confidential client using code flow + PKCE
                options.ClientId = "interactive.confidential.short";
                options.ClientSecret = "secret";
                options.ResponseType = "code";
                options.ResponseMode = "query";

                options.MapInboundClaims = false;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.SaveTokens = true;

                // request scopes + refresh tokens
                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("api");
                options.Scope.Add("offline_access");

                options.TokenValidationParameters.NameClaimType = "name";
                options.TokenValidationParameters.RoleClaimType = "role";

                options.EventsType = typeof(OidcEvents);
            });

        // adds access token management
        builder.Services.AddOpenIdConnectAccessTokenManagement();

        // not allowed to programmatically use HttpContext in Blazor Server.
        // that's why tokens cannot be managed in the login session
        builder.Services.AddSingleton<IUserTokenStore, ServerSideTokenStore>();

        // registers HTTP client that uses the managed user access token
        builder.Services.AddTransient<RemoteApiService>();
        builder.Services.AddHttpClient<RemoteApiService>(client =>
        {
            client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/");
        });

        builder.Services.AddAuthorization(options =>
        {
            // By default, all incoming requests will be authorized according to the default policy
            // comment out if you want to drive the login/logout workflow from the UI
            options.FallbackPolicy = options.DefaultPolicy;
        });

        builder.Services.AddControllersWithViews();
        builder.Services.AddRazorPages();
        builder.Services.AddServerSideBlazor();
        
        builder.Services.AddSingleton<WeatherForecastService>();
        
        return builder.Build();
    }

    public static WebApplication ConfigurePipeline(this WebApplication app)
    {
        app.UseSerilogRequestLogging();
        
        app.UseStaticFiles();

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapDefaultControllerRoute();
        app.MapBlazorHub();
        app.MapFallbackToPage("/_Host");
        
        return app;
    }
}