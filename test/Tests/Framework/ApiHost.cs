// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Duende.IdentityServer.Models;
using Microsoft.AspNetCore.Builder;
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
            // endpoints.Map("/{**catch-all}", async context =>
            // {
            //     // capture body if present
            //     var body = default(string);
            //     if (context.Request.HasJsonContentType())
            //     {
            //         using (var sr = new StreamReader(context.Request.Body))
            //         {
            //             body = await sr.ReadToEndAsync();
            //         }
            //     }
            //     
            //     // capture request headers
            //     var requestHeaders = new Dictionary<string, List<string>>();
            //     foreach (var header in context.Request.Headers)
            //     {
            //         var values = new List<string>(header.Value.Select(v => v));
            //         requestHeaders.Add(header.Key, values);
            //     }
            //
            //     var response = new ApiResponse(
            //         context.Request.Method,
            //         context.Request.Path.Value,
            //         context.User.FindFirst(("sub"))?.Value,
            //         context.User.FindFirst(("client_id"))?.Value,
            //         context.User.Claims.Select(x => new ClaimRecord(x.Type, x.Value)).ToArray())
            //     {
            //         Body = body,
            //         RequestHeaders = requestHeaders
            //     };
            //
            //     context.Response.StatusCode = ApiStatusCodeToReturn ?? 200;
            //     ApiStatusCodeToReturn = null;
            //
            //     context.Response.ContentType = "application/json";
            //     await context.Response.WriteAsync(JsonSerializer.Serialize(response));
            // });
        });
    }
}