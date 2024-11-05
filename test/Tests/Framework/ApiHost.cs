// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Duende.IdentityServer.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Duende.AccessTokenManagement.Tests;

public class ApiHost : GenericHost
{
    public int? ApiStatusCodeToReturn { get; set; }

    private readonly IdentityServerHost _identityServerHost;
    public event Action<Microsoft.AspNetCore.Http.HttpContext> ApiInvoked = ctx => { };
        
    public ApiHost(IdentityServerHost identityServerHost, string scope, string baseAddress = "https://api", string resource = "urn:api") 
        : base(baseAddress)
    {
        _identityServerHost = identityServerHost;
        _identityServerHost.ApiScopes.Add(new ApiScope(scope));
        _identityServerHost.ApiResources.Add(new ApiResource(resource));

        OnConfigureServices += ConfigureServices;
        OnConfigure += Configure;
    }

    private void ConfigureServices(IServiceCollection services)
    {
        services.AddRouting();
        services.AddAuthorization();

        services.AddAuthentication("token")
            .AddJwtBearer("token", options =>
            {
                options.Authority = _identityServerHost.Url();
                options.Audience = _identityServerHost.Url("/resources");
                options.MapInboundClaims = false;
                options.BackchannelHttpHandler = _identityServerHost.Server.CreateHandler();
                options.TokenValidationParameters.NameClaimType = "sub";
            });
    }

    private void Configure(IApplicationBuilder app)
    {
        app.Use(async(context, next) => 
        {
            ApiInvoked.Invoke(context);
            if (ApiStatusCodeToReturn != null)
            {
                context.Response.StatusCode = ApiStatusCodeToReturn.Value;
                ApiStatusCodeToReturn = null;
                return;
            }

            await next();
        });

        app.UseRouting();

        app.UseAuthentication();
        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.Map("/{**catch-all}", (HttpContext context) =>
            {
                return new TokenEchoResponse(
                    context.User.Identity?.Name ?? "missing sub", 
                    context.Request.Headers.Authorization.First() ?? "missing token");
            });
        });
    }
}