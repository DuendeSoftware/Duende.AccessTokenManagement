// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Net.Http;
using System.Threading.Tasks;

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <summary>
/// Configures OpenIdConnectOptions for user token management
/// </summary>
public class ConfigureOpenIdConnectOptions : IConfigureNamedOptions<OpenIdConnectOptions>
{
    private readonly IDPoPNonceStore _dPoPNonceStore;
    private readonly IDPoPProofService _dPoPProofService;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IOptions<UserTokenManagementOptions> _userAccessTokenManagementOptions;

    private readonly ILoggerFactory _loggerFactory;

    private readonly string? _configScheme;
    private readonly string _clientName;

    /// <summary>
    /// ctor
    /// </summary>
    public ConfigureOpenIdConnectOptions(
        IDPoPNonceStore dPoPNonceStore,
        IDPoPProofService dPoPProofService,
        IHttpContextAccessor httpContextAccessor,
        IOptions<UserTokenManagementOptions> userAccessTokenManagementOptions,
        IAuthenticationSchemeProvider schemeProvider,
        ILoggerFactory loggerFactory)
    {
        _dPoPNonceStore = dPoPNonceStore;
        _dPoPProofService = dPoPProofService;
        _httpContextAccessor = httpContextAccessor;
        _userAccessTokenManagementOptions = userAccessTokenManagementOptions;

        _configScheme = _userAccessTokenManagementOptions.Value.ChallengeScheme;
        if (string.IsNullOrWhiteSpace(_configScheme))
        {
            var defaultScheme = schemeProvider.GetDefaultChallengeSchemeAsync().ConfigureAwait(false).GetAwaiter().GetResult();

            if (defaultScheme is null)
            {
                throw new InvalidOperationException(
                    "No OpenID Connect authentication scheme configured for getting client configuration. Either set the scheme name explicitly or set the default challenge scheme");
            }

            _configScheme = defaultScheme.Name;
        }

        _clientName = OpenIdConnectTokenManagementDefaults.ClientCredentialsClientNamePrefix + _configScheme;
        _loggerFactory = loggerFactory;
    }

    /// <inheritdoc/>
    public void Configure(OpenIdConnectOptions options)
    {
    }

    /// <inheritdoc/>
    public void Configure(string? name, OpenIdConnectOptions options)
    {
        if (_configScheme == name)
        {
            // add the event handling to enable DPoP for this OIDC client
            options.Events.OnRedirectToIdentityProvider = CreateCallback(options.Events.OnRedirectToIdentityProvider);
            options.Events.OnAuthorizationCodeReceived = CreateCallback(options.Events.OnAuthorizationCodeReceived);
            options.Events.OnTokenValidated = CreateCallback(options.Events.OnTokenValidated);

            options.BackchannelHttpHandler = new AuthorizationServerDPoPHandler(_dPoPProofService, _dPoPNonceStore, _httpContextAccessor, _loggerFactory)
            {
                InnerHandler = options.BackchannelHttpHandler ?? new HttpClientHandler()
            };
        }
    }

    private Func<RedirectContext, Task> CreateCallback(Func<RedirectContext, Task> inner)
    {
        async Task Callback(RedirectContext context)
        {
            if (inner != null)
            {
                await inner.Invoke(context);
            }

            var dPoPKeyStore = context.HttpContext.RequestServices.GetRequiredService<IDPoPKeyStore>();

            var key = await dPoPKeyStore.GetKeyAsync(_clientName);
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
                    // we store the proof key here to associate it with the
                    // authorization code that will be returned. Ultimately we
                    // use this to provide proof of possession during code
                    // exchange.
                    context.Properties.SetProofKey(key.JsonWebKey);

                    // pass jkt to authorize endpoint
                    context.ProtocolMessage.Parameters[OidcConstants.AuthorizeRequest.DPoPKeyThumbprint] = jkt;
                }
            }
        };

        return Callback;
    }

    private Func<AuthorizationCodeReceivedContext, Task> CreateCallback(Func<AuthorizationCodeReceivedContext, Task> inner)
    {
        Task Callback(AuthorizationCodeReceivedContext context)
        {
            var result = inner?.Invoke(context) ?? Task.CompletedTask;

            // get key from storage
            var jwk = context.Properties?.GetProofKey();
            if (jwk != null)
            {
                // set it so the OIDC message handler can find it
                context.HttpContext.SetCodeExchangeDPoPKey(jwk);
            }

            return result;
        };

        return Callback;
    }

    private Func<TokenValidatedContext, Task> CreateCallback(Func<TokenValidatedContext, Task> inner)
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
