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
        private const string DPoPKeyName = "dpop_proof_key";

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

            var tokens = result.Properties.Items.Where(i => i.Key.StartsWith(TokenPrefix)).ToList();
            if (!tokens.Any())
            {
                _logger.LogInformation("No tokens found in cookie properties. SaveTokens must be enabled for automatic token refresh.");

                return new UserToken() { Error = "No tokens in properties" };
            }

            var tokenName = NamePrefixAndResourceSuffix(OpenIdConnectParameterNames.AccessToken, parameters);
            var tokenTypeName = NamePrefixAndResourceSuffix(OpenIdConnectParameterNames.TokenType, parameters);
            var dpopKeyName = NamePrefixAndResourceSuffix(DPoPKeyName, parameters);
            var expiresName = NamePrefixAndResourceSuffix("expires_at", parameters);
            
            // Note that we are not including the the resource suffix because there is no per-resource refresh token
            var refreshTokenName = NamePrefix(OpenIdConnectParameterNames.RefreshToken);

            var appendChallengeScheme = AppendChallengeSchemeToTokenNames(parameters);

            var accessToken = GetTokenValue(tokens, tokenName, appendChallengeScheme, parameters);
            var accessTokenType = GetTokenValue(tokens, tokenTypeName, appendChallengeScheme, parameters);
            var dpopKey = GetTokenValue(tokens, dpopKeyName, appendChallengeScheme, parameters);
            var expiresAt = GetTokenValue(tokens, expiresName, appendChallengeScheme, parameters);
            var refreshToken = GetTokenValue(tokens, refreshTokenName, appendChallengeScheme, parameters);

            DateTimeOffset dtExpires = DateTimeOffset.MaxValue;
            if (expiresAt != null)
            {
                dtExpires = DateTimeOffset.Parse(expiresAt, CultureInfo.InvariantCulture);
            }

            return new UserToken
            {
                AccessToken = accessToken,
                AccessTokenType = accessTokenType,
                DPoPJsonWebKey = dpopKey,
                RefreshToken = refreshToken,
                Expiration = dtExpires
            };
        }

        // If we are using the challenge scheme, we try to get the token 2 ways
        // (with and without the suffix). This is necessary because ASP.NET
        // itself does not set the suffix, so we might not have one at all.
        private static string? GetTokenValue(List<KeyValuePair<string, string?>> tokens, string key, bool appendChallengeScheme, UserTokenRequestParameters parameters)
        {
            string? token = null;

            if(appendChallengeScheme)
            {
                var scheme = parameters.ChallengeScheme;
                token = GetTokenValue(tokens, ChallengeSuffix(key, scheme!));
            }

            if (token.IsMissing())
            {
                token = GetTokenValue(tokens, key);
            }
            return token;
        }
        
        private static string? GetTokenValue(List<KeyValuePair<string, string?>> tokens, string key)
        {
            return tokens.SingleOrDefault(t => t.Key == key).Value;
        }

        /// Adds the .Token. prefix to the token name and, if the resource
        /// parameter was included, the suffix marking this token as
        /// per-resource.
        private static string NamePrefixAndResourceSuffix(string type, UserTokenRequestParameters parameters) 
        {
            var result = NamePrefix(type);
            if(!string.IsNullOrEmpty(parameters.Resource))
            {
                result = ResourceSuffix(result, parameters.Resource);
            }
            return result;
        }

        private static string NamePrefix(string name) => $"{TokenPrefix}{name}";

        private static string ResourceSuffix(string name, string resource) => $"{name}::{resource}";

        private static string ChallengeSuffix(string name, string challengeScheme) => $"{name}||{challengeScheme}";


        /// <inheritdoc/>
        public async Task StoreTokenAsync(
            ClaimsPrincipal user,
            UserToken token,
            UserTokenRequestParameters? parameters = null)
        {
            parameters ??= new();

            // check the cache in case the cookie was re-issued via StoreTokenAsync
            // we use String.Empty as the key for a null SignInScheme
            if (!_cache.TryGetValue(parameters.SignInScheme ?? String.Empty, out var result))
            {
                result = await _contextAccessor!.HttpContext!.AuthenticateAsync(parameters.SignInScheme)!.ConfigureAwait(false);
            }

            if (result is not { Succeeded: true })
            {
                throw new Exception("Can't store tokens. User is anonymous");
            }

            // in case you want to filter certain claims before re-issuing the authentication session
            var transformedPrincipal = await FilterPrincipalAsync(result.Principal!).ConfigureAwait(false);

            var tokenName = NamePrefixAndResourceSuffix(OpenIdConnectParameterNames.AccessToken, parameters);
            var tokenTypeName = NamePrefixAndResourceSuffix(OpenIdConnectParameterNames.TokenType, parameters);
            var dpopKeyName = NamePrefixAndResourceSuffix(DPoPKeyName, parameters);
            var expiresName = NamePrefixAndResourceSuffix("expires_at", parameters);
            
            // Note that we are not including the the resource suffix because there is no per-resource refresh token
            var refreshTokenName = NamePrefix(OpenIdConnectParameterNames.RefreshToken);
            
            if (AppendChallengeSchemeToTokenNames(parameters))
            {
                string challengeScheme = parameters.ChallengeScheme!;
                tokenName = ChallengeSuffix(tokenName, challengeScheme);
                tokenTypeName = ChallengeSuffix(tokenTypeName, challengeScheme);
                dpopKeyName = ChallengeSuffix(dpopKeyName, challengeScheme);
                expiresName = ChallengeSuffix(expiresName, challengeScheme);
                refreshTokenName = ChallengeSuffix(refreshTokenName, challengeScheme);
            }

            result.Properties!.Items[tokenName] = token.AccessToken;
            result.Properties!.Items[tokenTypeName] = token.AccessTokenType;
            if (token.DPoPJsonWebKey != null)
            {
                result.Properties!.Items[dpopKeyName] = token.DPoPJsonWebKey;
            }
            result.Properties!.Items[expiresName] = token.Expiration.ToString("o", CultureInfo.InvariantCulture);

            if (token.RefreshToken != null)
            {
                if (!result.Properties.UpdateTokenValue(refreshTokenName, token.RefreshToken))
                {
                    result.Properties.Items[$"{TokenPrefix}{refreshTokenName}"] = token.RefreshToken;
                }
            }

            var options = _contextAccessor!.HttpContext!.RequestServices.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>();
            var schemeProvider = _contextAccessor.HttpContext.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();
            var scheme = parameters.SignInScheme ?? (await schemeProvider.GetDefaultSignInSchemeAsync().ConfigureAwait(false))?.Name;
            var cookieOptions = options.Get(scheme);

            if (result.Properties.AllowRefresh == true ||
                (result.Properties.AllowRefresh == null && cookieOptions.SlidingExpiration))
            {
                // this will allow the cookie to be issued with a new issued (and thus a new expiration)
                result.Properties.IssuedUtc = null;
                result.Properties.ExpiresUtc = null;
            }

            result.Properties.Items.Remove(TokenNamesKey);
            var tokenNames = result.Properties.Items
                .Where(item => item.Key.StartsWith(TokenPrefix))
                .Select(item => item.Key.Substring(TokenPrefix.Length));
            result.Properties.Items.Add(new KeyValuePair<string, string?>(TokenNamesKey, string.Join(";", tokenNames)));

            await _contextAccessor.HttpContext.SignInAsync(parameters.SignInScheme, transformedPrincipal, result.Properties).ConfigureAwait(false);

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
            return _options.UseChallengeSchemeScopedTokens && !string.IsNullOrEmpty(parameters.ChallengeScheme);
        }
    }
}