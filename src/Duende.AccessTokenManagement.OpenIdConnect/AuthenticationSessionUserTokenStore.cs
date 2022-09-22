// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Duende.AccessTokenManagement.OpenIdConnect
{
    /// <summary>
    /// Token store using the ASP.NET Core authentication session
    /// </summary>
    public class AuthenticationSessionUserAccessTokenStore : IUserTokenStore
    {
        private const string TokenPrefix = ".Token.";
        private const string TokenNamesKey = ".TokenNames";

        private readonly IHttpContextAccessor _contextAccessor;
        private readonly ILogger<AuthenticationSessionUserAccessTokenStore> _logger;
        private readonly UserTokenManagementOptions _options;

        // per-request cache so that if SignInAsync is used, we won't re-read the old/cached AuthenticateResult from the handler
        // this requires this service to be added as scoped to the DI system
        private readonly Dictionary<string, AuthenticateResult> _cache = new Dictionary<string, AuthenticateResult>();

        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="contextAccessor"></param>
        /// <param name="logger"></param>
        /// <param name="options"></param>
        public AuthenticationSessionUserAccessTokenStore(
            IHttpContextAccessor contextAccessor,
            ILogger<AuthenticationSessionUserAccessTokenStore> logger, 
            IOptions<UserTokenManagementOptions> options)
        {
            _contextAccessor = contextAccessor ?? throw new ArgumentNullException(nameof(contextAccessor));
            _logger = logger;
            _options = options.Value;
        }

        /// <inheritdoc/>
        public async Task<UserToken> GetTokenAsync(
            ClaimsPrincipal user,
            UserTokenRequestParameters? parameters = null)
        {
            parameters ??= new();

            // check the cache in case the cookie was re-issued via StoreTokenAsync
            // we use String.Empty as the key for a null SignInScheme
            if (!_cache.TryGetValue(parameters.SignInScheme ?? String.Empty, out var result))
            {
                result = await _contextAccessor!.HttpContext!.AuthenticateAsync(parameters.SignInScheme);
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

            var tokens = result.Properties.Items.Where(i => i.Key.StartsWith(TokenPrefix)).ToList();
            if (!tokens.Any())
            {
                _logger.LogInformation("No tokens found in cookie properties. SaveTokens must be enabled for automatic token refresh.");

                return new UserToken() { Error = "No tokens in properties" };
            }

            var tokenName = $"{TokenPrefix}{OpenIdConnectParameterNames.AccessToken}";
            if (!string.IsNullOrEmpty(parameters.Resource))
            {
                tokenName += $"::{parameters.Resource}";
            }

            var expiresName = $"{TokenPrefix}expires_at"; string? refreshToken = null;
            string? accessToken = null;
            string? expiresAt = null;
            if (!string.IsNullOrEmpty(parameters.Resource))
            {
                expiresName += $"::{parameters.Resource}";
            }

            const string refreshTokenName = $"{TokenPrefix}{OpenIdConnectParameterNames.RefreshToken}";

            if (AppendChallengeSchemeToTokenNames(parameters))
            {
                refreshToken = tokens
                        .SingleOrDefault(t => t.Key == $"{refreshTokenName}||{parameters.ChallengeScheme}").Value;
                accessToken = tokens.SingleOrDefault(t => t.Key == $"{tokenName}||{parameters.ChallengeScheme}")
                    .Value;
                expiresAt = tokens.SingleOrDefault(t => t.Key == $"{expiresName}||{parameters.ChallengeScheme}")
                    .Value;
            }

            refreshToken ??= tokens.SingleOrDefault(t => t.Key == $"{refreshTokenName}").Value;
            accessToken ??= tokens.SingleOrDefault(t => t.Key == $"{tokenName}").Value;
            expiresAt ??= tokens.SingleOrDefault(t => t.Key == $"{expiresName}").Value;

            DateTimeOffset dtExpires = DateTimeOffset.MaxValue;
            if (expiresAt != null)
            {
                dtExpires = DateTimeOffset.Parse(expiresAt, CultureInfo.InvariantCulture);
            }

            return new UserToken
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                Expiration = dtExpires
            };
        }

        /// <inheritdoc/>
        public async Task StoreTokenAsync(
            ClaimsPrincipal user,
            UserToken token,
            UserTokenRequestParameters? parameters = null)
        {
            parameters ??= new ();

            // check the cache in case the cookie was re-issued via StoreTokenAsync
            // we use String.Empty as the key for a null SignInScheme
            if (!_cache.TryGetValue(parameters.SignInScheme ?? String.Empty, out var result))
            {
                result = await _contextAccessor!.HttpContext!.AuthenticateAsync(parameters.SignInScheme)!;
            }

            if (result is not { Succeeded: true })
            {
                throw new Exception("Can't store tokens. User is anonymous");
            }

            // in case you want to filter certain claims before re-issuing the authentication session
            var transformedPrincipal = await FilterPrincipalAsync(result.Principal!);

            var expiresName = "expires_at";
            if (!string.IsNullOrEmpty(parameters.Resource))
            {
                expiresName += $"::{parameters.Resource}";
            }

            var tokenName = OpenIdConnectParameterNames.AccessToken;
            if (!string.IsNullOrEmpty(parameters.Resource))
            {
                tokenName += $"::{parameters.Resource}";
            }

            var refreshTokenName = $"{OpenIdConnectParameterNames.RefreshToken}";

            if (AppendChallengeSchemeToTokenNames(parameters))
            {
                refreshTokenName += $"||{parameters.ChallengeScheme}";
                tokenName += $"||{parameters.ChallengeScheme}";
                expiresName += $"||{parameters.ChallengeScheme}";
            }

            result.Properties!.Items[$"{TokenPrefix}{tokenName}"] = token.AccessToken;
            result.Properties!.Items[$"{TokenPrefix}{expiresName}"] = token.Expiration.ToString("o", CultureInfo.InvariantCulture);

            if (token.RefreshToken != null)
            {
                if (!result.Properties.UpdateTokenValue(refreshTokenName, token.RefreshToken))
                {
                    result.Properties.Items[$"{TokenPrefix}{refreshTokenName}"] = token.RefreshToken;
                }
            }

            var options = _contextAccessor!.HttpContext!.RequestServices.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>();
            var schemeProvider = _contextAccessor.HttpContext.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();
            var scheme = parameters.SignInScheme ?? (await schemeProvider.GetDefaultSignInSchemeAsync())?.Name;
            var cookieOptions = options.Get(scheme);

            if (result.Properties.AllowRefresh == true ||
                (result.Properties.AllowRefresh == null && cookieOptions.SlidingExpiration))
            {
                // this will allow the cookie to be issued with a new issued (and thus a new expiration)
                result.Properties.IssuedUtc = null;
                result.Properties.ExpiresUtc = null;
            }

            result.Properties.Items.Remove(TokenNamesKey);
            result.Properties.Items.Add(new KeyValuePair<string, string?>(TokenNamesKey, string.Join(";", result.Properties.Items.Select(t => t.Key).ToList())));

            await _contextAccessor.HttpContext.SignInAsync(parameters.SignInScheme, transformedPrincipal, result.Properties);

            // add to the cache so if GetTokenAsync is called again, we will use the updated property values
            // we use String.Empty as the key for a null SignInScheme
            _cache[parameters.SignInScheme ?? String.Empty] = AuthenticateResult.Success(new AuthenticationTicket(transformedPrincipal, result.Properties, scheme!));
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

        /// <summary>
        /// Confirm application has opted in to UseChallengeSchemeScopedTokens and a ChallengeScheme is provided upon storage and retrieval of tokens.
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        protected virtual bool AppendChallengeSchemeToTokenNames(UserTokenRequestParameters parameters)
        {
            return _options.UseChallengeSchemeScopedTokens && !string.IsNullOrEmpty(parameters!.ChallengeScheme);
        }
    }
}