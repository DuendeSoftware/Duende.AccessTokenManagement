// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Duende.AccessTokenManagement.OpenIdConnect;
using Duende.IdentityServer.Models;
using IdentityModel;
using System.Security.Claims;

namespace Duende.AccessTokenManagement.Tests;

public class IntegrationTestBase
{
    protected readonly IdentityServerHost IdentityServerHost;
    protected ApiHost ApiHost;
    protected AppHost AppHost;

    public IntegrationTestBase(string clientId = "web", Action<UserTokenManagementOptions>? configureUserTokenManagementOptions = null)
    {
        IdentityServerHost = new IdentityServerHost();

        IdentityServerHost.Clients.Add(new Client
        {
            ClientId = "client_credentials_client",
            ClientSecrets = { new Secret("secret".Sha256()) },
            AllowedGrantTypes = GrantTypes.ClientCredentials,
            AllowedScopes = { "scope1" }
        });

        IdentityServerHost.Clients.Add(new Client
        {
            ClientId = "web",
            ClientSecrets = { new Secret("secret".Sha256()) },
            AllowedGrantTypes = GrantTypes.CodeAndClientCredentials,
            RedirectUris = { "https://app/signin-oidc" },
            PostLogoutRedirectUris = { "https://app/signout-callback-oidc" },
            AllowOfflineAccess = true,
            AllowedScopes = { "openid", "profile", "scope1" }
        });
        
        IdentityServerHost.Clients.Add(new Client
        {
            ClientId = "web.short",
            ClientSecrets = { new Secret("secret".Sha256()) },
            AllowedGrantTypes = GrantTypes.CodeAndClientCredentials,
            RedirectUris = { "https://app/signin-oidc" },
            PostLogoutRedirectUris = { "https://app/signout-callback-oidc" },
            AllowOfflineAccess = true,
            AllowedScopes = { "openid", "profile", "scope1" },
            
            AccessTokenLifetime = 10
        });

        IdentityServerHost.Clients.Add(new Client
        {
            ClientId = "dpop",
            ClientSecrets = { new Secret("secret".ToSha256()) },
            AllowedGrantTypes = GrantTypes.CodeAndClientCredentials,
            RedirectUris = { "https://app/signin-oidc" },
            PostLogoutRedirectUris = { "https://app/signout-callback-oidc" },
            AllowOfflineAccess = true,
            AllowedScopes = { "openid", "profile", "scope1" },

            RequireDPoP = true,
            DPoPValidationMode = DPoPTokenExpirationValidationMode.Nonce,
            DPoPClockSkew = TimeSpan.FromMilliseconds(10),

            AccessTokenLifetime = 10
        });

        IdentityServerHost.InitializeAsync().Wait();

        ApiHost = new ApiHost(IdentityServerHost, "scope1");
        ApiHost.InitializeAsync().Wait();

        AppHost = new AppHost(IdentityServerHost, ApiHost, clientId, configureUserTokenManagementOptions: configureUserTokenManagementOptions);
        AppHost.InitializeAsync().Wait();
    }

    public async Task Login(string sub)
    {
        await IdentityServerHost.IssueSessionCookieAsync(new Claim("sub", sub));
    }
}