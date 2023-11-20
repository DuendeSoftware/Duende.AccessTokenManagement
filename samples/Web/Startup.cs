// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using Serilog.Events;

namespace Web;

public static class Startup
{
    internal static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddControllersWithViews();

        builder.Services.AddAuthentication(options =>
            {
                options.DefaultScheme = "cookie";
                options.DefaultChallengeScheme = "oidc";
            })
            .AddCookie("cookie", options =>
            {
                options.Cookie.Name = "web";

                options.Events.OnSigningOut = async e => { await e.HttpContext.RevokeRefreshTokenAsync(); };
            })
            .AddOpenIdConnect("oidc", options =>
            {
                options.Authority = "https://demo.duendesoftware.com";
                //options.Authority = "https://localhost:5001";

                options.ClientId = "interactive.confidential.short";
                options.ClientSecret = "secret";

                options.ResponseType = "code";
                options.ResponseMode = "query";

                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("email");
                options.Scope.Add("offline_access");
                options.Scope.Add("api");
                options.Scope.Add("resource1.scope1");

                options.GetClaimsFromUserInfoEndpoint = true;
                options.SaveTokens = true;
                options.MapInboundClaims = false;

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = "role"
                };

                options.Events.OnRedirectToIdentityProvider = ctx => 
                {
                    ctx.ProtocolMessage.Resource = "urn:resource1";
                    return Task.CompletedTask;
                };
            });

        var rsaKey = new RsaSecurityKey(RSA.Create(2048));
        var jsonWebKey = JsonWebKeyConverter.ConvertFromRSASecurityKey(rsaKey);
        jsonWebKey.Alg = "PS256";
        var jwk = JsonSerializer.Serialize(jsonWebKey);
        
        builder.Services.AddOpenIdConnectAccessTokenManagement(options => 
        {
            // if you uncomment this line, then be sure to change the URL for the "user_client"
            // to include "dpop/" at the end, since that's the DPoP enabled API path
            options.DPoPJsonWebKey = jwk;
        });

        // registers HTTP client that uses the managed user access token
        builder.Services.AddUserAccessTokenHttpClient("user_client",
            configureClient: client => {
                //client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/");
                client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/dpop/");
            });

        // registers HTTP client that uses the managed client access token
        builder.Services.AddClientAccessTokenHttpClient("client",
            configureClient: client => { client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/dpop/"); });

        // registers a typed HTTP client with token management support
        builder.Services.AddHttpClient<TypedUserClient>(client =>
            {
                client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/dpop/");
            })
            .AddUserAccessTokenHandler();

        builder.Services.AddHttpClient<TypedClientClient>(client =>
            {
                client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/dpop/");
            })
            .AddClientAccessTokenHandler();

        return builder.Build();
    }

    internal static WebApplication ConfigurePipeline(this WebApplication app)
    {
        app.UseSerilogRequestLogging(
            options => options.GetLevel = (httpContext, elapsed, ex) => LogEventLevel.Debug);

        app.UseDeveloperExceptionPage();
        app.UseHttpsRedirection();
        app.UseStaticFiles();

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapDefaultControllerRoute()
            .RequireAuthorization();
        
        return app;
    }
}