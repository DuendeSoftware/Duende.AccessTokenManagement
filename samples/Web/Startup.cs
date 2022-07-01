using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Serilog;

namespace MvcCode;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddControllersWithViews();

        services.AddAuthentication(options =>
            {
                options.DefaultScheme = "cookie";
                options.DefaultChallengeScheme = "oidc";
            })
            .AddCookie("cookie", options =>
            {
                options.Cookie.Name = "web";

                options.Events.OnSigningOut = async e =>
                {
                    await e.HttpContext.RevokeRefreshTokenAsync();
                };
            })
            .AddOpenIdConnect("oidc", options =>
            {
                options.Authority = "https://demo.duendesoftware.com";

                options.ClientId = "interactive.confidential.short";
                options.ClientSecret = "secret";

                // code flow + PKCE (PKCE is turned on by default)
                options.ResponseType = "code";
                options.UsePkce = true;

                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("email");
                options.Scope.Add("offline_access");
                options.Scope.Add("api");

                // not mapped by default
                options.ClaimActions.MapJsonKey("website", "website");

                // keeps id_token smaller
                options.GetClaimsFromUserInfoEndpoint = true;
                options.SaveTokens = true;
                options.MapInboundClaims = false;

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = "role"
                };
            });

        services.AddOpenIdConnectTokenManagement();
        
        // registers HTTP client that uses the managed user access token
        services.AddUserAccessTokenHttpClient("user_client", configureClient: client =>
        {
            client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/");
        });
        
        // registers HTTP client that uses the managed client access token
        services.AddClientAccessTokenHttpClient("client", configureClient: client =>
        {
            client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/");
        });

        // // adds user and client access token management
        // services.AddAccessTokenManagement(options =>
        //     {
        //         // client config is inferred from OpenID Connect settings
        //         // if you want to specify scopes explicitly, do it here, otherwise the scope parameter will not be sent
        //         options.Client.DefaultClient.Scope = "api";
        //     })
        //     .ConfigureBackchannelHttpClient()
        //         .AddTransientHttpErrorPolicy(policy => policy.WaitAndRetryAsync(new[]
        //         {
        //             TimeSpan.FromSeconds(1),
        //             TimeSpan.FromSeconds(2),
        //             TimeSpan.FromSeconds(3)
        //         }));
        //
        

        // registers HTTP client that uses the managed client access token
        // services.AddClientAccessTokenHttpClient("client", configureClient: client =>
        // {
        //     client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/");
        // });
        //
        // // registers a typed HTTP client with token management support
        // services.AddHttpClient<TypedUserClient>(client =>
        // {
        //     client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/");
        // })
        //     .AddUserAccessTokenHandler();
        //
        // services.AddHttpClient<TypedClientClient>(client =>
        // {
        //     client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/");
        // })
        //     .AddClientAccessTokenHandler();
    }

    public void Configure(IApplicationBuilder app)
    {
        app.UseSerilogRequestLogging();
        
        app.UseDeveloperExceptionPage();
        app.UseHttpsRedirection();
        app.UseStaticFiles();

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapDefaultControllerRoute()
                .RequireAuthorization();
        });
    }
}