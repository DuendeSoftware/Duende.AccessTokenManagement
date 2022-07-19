// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using Duende.AccessTokenManagement;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using Serilog.Events;

namespace WebJarJwt;

public static class Startup
{
    internal static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddControllersWithViews();
        builder.Services.AddTransient<OidcEvents>();

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
                options.ClientId = "interactive.confidential.short.jar.jwt";
                
                options.ResponseType = "code";
                options.ResponseMode = "query";

                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("email");
                options.Scope.Add("offline_access");
                options.Scope.Add("resource1.scope1");

                options.GetClaimsFromUserInfoEndpoint = true;
                options.SaveTokens = true;
                options.MapInboundClaims = false;

                options.EventsType = typeof(OidcEvents);

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = "role"
                };
            });

        builder.Services.AddOpenIdConnectAccessTokenManagement();
        builder.Services.AddTransient<IClientAssertionService, ClientAssertionService>();

        // registers HTTP client that uses the managed user access token
        builder.Services.AddUserAccessTokenHttpClient("user_client",
            configureClient: client => { client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/"); });

        // registers HTTP client that uses the managed client access token
        builder.Services.AddClientAccessTokenHttpClient("client",
            configureClient: client => { client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/"); });

        // registers a typed HTTP client with token management support
        builder.Services.AddHttpClient<TypedUserClient>(client =>
            {
                client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/");
            })
            .AddUserAccessTokenHandler();

        builder.Services.AddHttpClient<TypedClientClient>(client =>
            {
                client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/");
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