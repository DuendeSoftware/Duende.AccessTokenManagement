// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <summary>
/// Configures OpenIdConnectOptions for user token management
/// </summary>
public class PostConfigureOpenIdConnectOptions : IPostConfigureOptions<OpenIdConnectOptions>
{
    private readonly IDPoPNonceStore _dPoPNonceStore;
    private readonly IDPoPProofService _dPoPProofService;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IOptions<UserTokenManagementOptions> _userAccessTokenManagementOptions;
    private readonly string? _configScheme;

    /// <summary>
    /// ctor
    /// </summary>
    public PostConfigureOpenIdConnectOptions(
        IDPoPNonceStore dPoPNonceStore,
        IDPoPProofService dPoPProofService,
        IHttpContextAccessor httpContextAccessor,
        IOptions<UserTokenManagementOptions> userAccessTokenManagementOptions,
        IAuthenticationSchemeProvider schemeProvider)
    {
        _dPoPNonceStore = dPoPNonceStore;
        _dPoPProofService = dPoPProofService;
        _httpContextAccessor = httpContextAccessor;
        _userAccessTokenManagementOptions = userAccessTokenManagementOptions;

        _configScheme = _userAccessTokenManagementOptions.Value.ChallengeScheme;
    }

    /// <inheritdoc/>
    public void PostConfigure(string name, OpenIdConnectOptions options)
    {
        // if name is not equal to configured name do nothing
        if (!string.IsNullOrWhiteSpace(_configScheme) && _configScheme != name)
        {
            return;
        }
        if (!string.IsNullOrWhiteSpace(name))
        {
            // add the event handling to enable DPoP for this OIDC client
            options.Events.OnRedirectToIdentityProvider = CreateCallback(options.Events.OnRedirectToIdentityProvider, name);
            options.Events.OnAuthorizationCodeReceived = CreateCallback(options.Events.OnAuthorizationCodeReceived, name);
            options.Events.OnTokenValidated = CreateCallback(options.Events.OnTokenValidated, name);

            options.BackchannelHttpHandler = new DPoPProofTokenHandler(_dPoPProofService, _dPoPNonceStore, _httpContextAccessor)
            {
                InnerHandler = options.BackchannelHttpHandler ?? new HttpClientHandler()
            };
        }
    }

    private Func<RedirectContext, Task> CreateCallback(Func<RedirectContext, Task> inner, string scheme)
    {
        async Task Callback(RedirectContext context)
        {
            var clientName = OpenIdConnectTokenManagementDefaults.ClientCredentialsClientNamePrefix + scheme;
            if (inner != null)
            {
                await inner.Invoke(context);
            }

            var dPoPKeyStore = context.HttpContext.RequestServices.GetRequiredService<IDPoPKeyStore>();

            var key = await dPoPKeyStore.GetKeyAsync(clientName);
            if (key != null)
            {
                var jkt = _dPoPProofService.GetProofKeyThumbprint(new DPoPProofRequest
                {
                    Url = context.ProtocolMessage.AuthorizationEndpoint,
                    Method = "GET",
                    DPoPJsonWebKey = key.JsonWebKey,
                });

                // checking for null allows for opt-out from using DPoP
                if (jkt != null)
                {
                    // we store the proof key here to associate it with the access token returned
                    context.Properties.SetProofKey(key.JsonWebKey);

                    // pass jkt to authorize endpoint
                    context.ProtocolMessage.Parameters[OidcConstants.AuthorizeRequest.DPoPKeyThumbprint] = jkt;
                }
            }
        };

        return Callback;
    }

    private Func<AuthorizationCodeReceivedContext, Task> CreateCallback(Func<AuthorizationCodeReceivedContext, Task> inner, string scheme)
    {
        Task Callback(AuthorizationCodeReceivedContext context)
        {
            var result = inner?.Invoke(context) ?? Task.CompletedTask;

            // get key from storage
            var jwk = context.Properties?.GetProofKey();
            if (jwk != null)
            {
                // set it so the OIDC message handler can find it
                context.HttpContext.SetOutboundProofKey(jwk);
            }

            return result;
        };

        return Callback;
    }

    private Func<TokenValidatedContext, Task> CreateCallback(Func<TokenValidatedContext, Task> inner, string scheme)
    {
        Task Callback(TokenValidatedContext context)
        {
            var result = inner?.Invoke(context) ?? Task.CompletedTask;

            // TODO: we don't have a good approach for this right now, since the IUserTokenStore
            // just assumes that the session management has been populated with all the token values
            //
            // get key from storage
            //var jwk = context.Properties?.GetProofKey();
            //if (jwk != null)
            //{
            //    // clear this so the properties are not bloated
            //    // and defer to the host and/or IUserTokenStore implementation to decide where the key is kept
            //    //context.Properties!.RemoveProofKey();
            //}

            return result;
        };

        return Callback;
    }
}
