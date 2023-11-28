﻿// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using RichardSzalay.MockHttp;
using Microsoft.Extensions.Options;

namespace Duende.AccessTokenManagement.Tests;

public class AppHost : GenericHost
{
    private readonly IdentityServerHost _identityServerHost;
    private readonly ApiHost _apiHost;
    private readonly string _clientId;
        
    public AppHost(
        IdentityServerHost identityServerHost, 
        ApiHost apiHost, 
        string clientId,
        string baseAddress = "https://app")
        : base(baseAddress)
    {
        _identityServerHost = identityServerHost;
        _apiHost = apiHost;
        _clientId = clientId;

        OnConfigureServices += ConfigureServices;
        OnConfigure += Configure;
    }

    public MockHttpMessageHandler? IdentityServerHttpHandler { get; set; }

    private void ConfigureServices(IServiceCollection services)
    {
        services.AddRouting();
        services.AddAuthorization();

        services.AddAuthentication("cookie")
            .AddCookie("cookie", options =>
            {
                options.Cookie.Name = "bff";
            });

        services.AddAuthentication(options =>
            {
                options.DefaultChallengeScheme = "oidc";
                options.DefaultSignOutScheme = "oidc";
            })
            .AddOpenIdConnect("oidc", options =>
            {
                options.Authority = _identityServerHost.Url();

                options.ClientId = _clientId;
                options.ClientSecret = "secret";
                options.ResponseType = "code";
                options.ResponseMode = "query";

                options.MapInboundClaims = false;
                options.GetClaimsFromUserInfoEndpoint = false;
                options.SaveTokens = true;

                options.Scope.Clear();
                var client = _identityServerHost.Clients.Single(x => x.ClientId == _clientId);
                foreach (var scope in client.AllowedScopes)
                {
                    options.Scope.Add(scope);
                }

                if (client.AllowOfflineAccess)
                {
                    options.Scope.Add("offline_access");
                }

                var identityServerHandler = _identityServerHost.Server.CreateHandler();   
                if (IdentityServerHttpHandler != null)
                {
                    // allow discovery document
                    IdentityServerHttpHandler.When("/.well-known/*")
                        .Respond(identityServerHandler);
                    
                    options.BackchannelHttpHandler = IdentityServerHttpHandler;

                    // *** WIP ***
                    //
                    // This technique doesn't work as is, because the http
                    // client is created after the post configure options runs.
                    // We might be able to refactor the discovery caches to
                    // initialize themselves on demand, rather than as part of a
                    // post configure. We should also think about how to make
                    // the testing easier, because right now we have to specify
                    // an IdentityServeHttpHandler in the test
                    // Anonymous_user_should_return_client_token, even though we
                    // don't need that handler in the test (otherwise we don't
                    // get into this branch of code). That makes it weird to
                    // understand the test, because it depends on the
                    // implementation details of the host so closely.
                    services.AddHttpClient<ConfigureDiscoveryCache>(h => 
                        h = new HttpClient(IdentityServerHttpHandler));
                }
                else
                {
                    options.BackchannelHttpHandler = identityServerHandler;
                }

                options.ProtocolValidator.RequireNonce = false;
            });

        services.AddSingleton<IPostConfigureOptions<ClientCredentialsClient>, ConfigureDiscoveryCache>();

        services.AddDistributedMemoryCache();
        services.AddOpenIdConnectAccessTokenManagement();

    }

    private void Configure(IApplicationBuilder app)
    {
        app.UseAuthentication();
        app.UseRouting();
        app.UseAuthorization();

        app.UseEndpoints(endpoints =>
        {
            endpoints.MapGet("/login", async context =>
            {
                await context.ChallengeAsync(new AuthenticationProperties
                {
                    RedirectUri = "/"
                });
            });
                
            endpoints.MapGet("/logout", async context =>
            {
                await context.SignOutAsync();
            });
            
            endpoints.MapGet("/user_token", async context =>
            {
                var token = await context.GetUserAccessTokenAsync();
                await context.Response.WriteAsJsonAsync(token);
            });
            
            endpoints.MapGet("/client_token", async context =>
            {
                var token = await context.GetClientAccessTokenAsync();
                await context.Response.WriteAsJsonAsync(token);
            });
        });
    }

    public async Task<HttpResponseMessage> LoginAsync(string sub, string? sid = null)
    {
        await _identityServerHost.CreateIdentityServerSessionCookieAsync(sub, sid);
        return await OidcLoginAsync();
    }

    public async Task<HttpResponseMessage> OidcLoginAsync()
    {
        var response = await BrowserClient.GetAsync(Url("/login"));
        response.StatusCode.ShouldBe((HttpStatusCode)302); // authorize
        response.Headers.Location!.ToString().ToLowerInvariant().ShouldStartWith(_identityServerHost.Url("/connect/authorize"));

        response = await _identityServerHost.BrowserClient.GetAsync(response.Headers.Location.ToString());
        response.StatusCode.ShouldBe((HttpStatusCode)302); // client callback
        response.Headers.Location!.ToString().ToLowerInvariant().ShouldStartWith(Url("/signin-oidc"));

        response = await BrowserClient.GetAsync(response.Headers.Location.ToString());
        response.StatusCode.ShouldBe((HttpStatusCode)302); // root
        response.Headers.Location!.ToString().ToLowerInvariant().ShouldBe("/");

        response = await BrowserClient.GetAsync(Url(response.Headers.Location.ToString()));
        return response;
    }

    public async Task<HttpResponseMessage> LogoutAsync(string? sid = null)
    {
        var response = await BrowserClient.GetAsync(Url("/logout") + "?sid=" + sid);
        response.StatusCode.ShouldBe((HttpStatusCode)302); // endsession
        response.Headers.Location!.ToString().ToLowerInvariant().ShouldStartWith(_identityServerHost.Url("/connect/endsession"));

        response = await _identityServerHost.BrowserClient.GetAsync(response.Headers.Location.ToString());
        response.StatusCode.ShouldBe((HttpStatusCode)302); // logout
        response.Headers.Location!.ToString().ToLowerInvariant().ShouldStartWith(_identityServerHost.Url("/account/logout"));

        response = await _identityServerHost.BrowserClient.GetAsync(response.Headers.Location.ToString());
        response.StatusCode.ShouldBe((HttpStatusCode)302); // post logout redirect uri
        response.Headers.Location!.ToString().ToLowerInvariant().ShouldStartWith(Url("/signout-callback-oidc"));

        response = await BrowserClient.GetAsync(response.Headers.Location.ToString());
        response.StatusCode.ShouldBe((HttpStatusCode)302); // root
        response.Headers.Location!.ToString().ToLowerInvariant().ShouldBe("/");

        response = await BrowserClient.GetAsync(Url(response.Headers.Location.ToString()));
        return response;
    }
}