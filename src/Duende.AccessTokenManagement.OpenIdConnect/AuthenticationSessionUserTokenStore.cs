// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using IdentityModel;

namespace Duende.AccessTokenManagement.OpenIdConnect
{
    /// <summary>
    /// Token store using the ASP.NET Core authentication session
    /// </summary>
    public class AuthenticationSessionUserAccessTokenStore : IUserTokenStore
    {
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly IStoreTokensInAuthenticationProperties _tokensInProps;
        private readonly ILogger<AuthenticationSessionUserAccessTokenStore> _logger;

        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="contextAccessor"></param>
        /// <param name="tokensInProps"></param>
        /// <param name="logger"></param>
        public AuthenticationSessionUserAccessTokenStore(
            IHttpContextAccessor contextAccessor,
            IStoreTokensInAuthenticationProperties tokensInProps,
            ILogger<AuthenticationSessionUserAccessTokenStore> logger)
        {
            _contextAccessor = contextAccessor ?? throw new ArgumentNullException(nameof(contextAccessor));
            _logger = logger;
            _tokensInProps = tokensInProps;
        }

        /// <inheritdoc/>
        public async Task<UserToken> GetTokenAsync(
            ClaimsPrincipal user,
            UserTokenRequestParameters? parameters = null)
        {
            parameters ??= new();
            // Resolve the cache here because it needs to have a per-request
            // lifetime. Sometimes the store itself is captured for longer than
            // that inside an HttpClient.
            var cache = _contextAccessor.HttpContext?.RequestServices.GetRequiredService<AuthenticateResultCache>();
         
            // check the cache in case the cookie was re-issued via StoreTokenAsync
            // we use String.Empty as the key for a null SignInScheme
            if (!cache!.TryGetValue(parameters.SignInScheme ?? String.Empty, out var result))
            {
                result = await _contextAccessor!.HttpContext!.AuthenticateAsync(parameters.SignInScheme).ConfigureAwait(false);
            }

            if (!result.Succeeded)
            {
                _logger.LogInformation("Cannot authenticate scheme: {scheme}", parameters.SignInScheme ?? "default signin scheme");

                return new UserToken() { Error = "Cannot authenticate scheme" };
            }

            if (result.Properties == null)
            {
                _logger.LogInformation("Authentication result properties are null for scheme: {scheme}",
                    parameters.SignInScheme ?? "default signin scheme");

                return new UserToken() { Error = "No properties on authentication result" };
            }

            return _tokensInProps.GetUserToken(result.Properties, parameters);
        }

        /// <inheritdoc/>
        public async Task StoreTokenAsync(
            ClaimsPrincipal user,
            UserToken token,
            UserTokenRequestParameters? parameters = null)
        {
            parameters ??= new();

            // Resolve the cache here because it needs to have a per-request
            // lifetime. Sometimes the store itself is captured for longer than
            // that inside an HttpClient.
            var cache = _contextAccessor.HttpContext?.RequestServices.GetRequiredService<AuthenticateResultCache>();

            // check the cache in case the cookie was re-issued via StoreTokenAsync
            // we use String.Empty as the key for a null SignInScheme
            if (!cache!.TryGetValue(parameters.SignInScheme ?? String.Empty, out var result))
            {
                result = await _contextAccessor.HttpContext!.AuthenticateAsync(parameters.SignInScheme)!.ConfigureAwait(false);
            }

            if (result is not { Succeeded: true })
            {
                throw new Exception("Can't store tokens. User is anonymous");
            }

            // in case you want to filter certain claims before re-issuing the authentication session
            var transformedPrincipal = await FilterPrincipalAsync(result.Principal!).ConfigureAwait(false);

            _tokensInProps.SetUserToken(token, result.Properties, parameters);

            var scheme = await _tokensInProps.GetSchemeAsync(parameters);

            await _contextAccessor.HttpContext!.SignInAsync(scheme, transformedPrincipal, result.Properties).ConfigureAwait(false);

            // add to the cache so if GetTokenAsync is called again, we will use the updated property values
            // we use String.Empty as the key for a null SignInScheme
            cache[parameters.SignInScheme ?? String.Empty] = AuthenticateResult.Success(new AuthenticationTicket(transformedPrincipal, result.Properties, scheme!));
        }

        /// <inheritdoc/>
        public Task ClearTokenAsync(
            ClaimsPrincipal user, 
            UserTokenRequestParameters? parameters = null)
        {
            // don't bother here, since likely we're in the middle of signing out
            return Task.CompletedTask;
        }

        /// <summary>
        /// Allows transforming the principal before re-issuing the authentication session
        /// </summary>
        /// <param name="principal"></param>
        /// <returns></returns>
        protected virtual Task<ClaimsPrincipal> FilterPrincipalAsync(ClaimsPrincipal principal)
        {
            return Task.FromResult(principal);
        }
    }
}
