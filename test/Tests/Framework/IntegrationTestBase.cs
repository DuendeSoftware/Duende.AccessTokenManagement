// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

namespace Duende.AccessTokenManagement.Tests;

public class IntegrationTestBase
{
    protected readonly IdentityServerHost IdentityServerHost;
    protected ApiHost ApiHost;
    protected AppHost AppHost;

    public IntegrationTestBase()
    {
        IdentityServerHost = new IdentityServerHost();
            
        IdentityServerHost.Clients.Add(new Client
        {
            ClientId = "spa",
            ClientSecrets = { new Secret("secret".Sha256()) },
            AllowedGrantTypes = GrantTypes.CodeAndClientCredentials,
            RedirectUris = { "https://app/signin-oidc" },
            PostLogoutRedirectUris = { "https://app/signout-callback-oidc" },
            BackChannelLogoutUri = "https://app/bff/backchannel",
            AllowOfflineAccess = true,
            AllowedScopes = { "openid", "profile", "scope1" }
        });
            
            
        IdentityServerHost.OnConfigureServices += services => {
            services.AddTransient<IBackChannelLogoutHttpClient>(provider => 
                new DefaultBackChannelLogoutHttpClient(
                    AppHost.HttpClient, 
                    provider.GetRequiredService<ILoggerFactory>(), 
                    provider.GetRequiredService<ICancellationTokenProvider>()));
        };
            
        IdentityServerHost.InitializeAsync().Wait();

        ApiHost = new ApiHost(IdentityServerHost, "scope1");
        ApiHost.InitializeAsync().Wait();

        AppHost = new AppHost(IdentityServerHost, ApiHost, "spa");
        AppHost.InitializeAsync().Wait();
    }

    public async Task Login(string sub)
    {
        await IdentityServerHost.IssueSessionCookieAsync(new Claim("sub", sub));
    }
}