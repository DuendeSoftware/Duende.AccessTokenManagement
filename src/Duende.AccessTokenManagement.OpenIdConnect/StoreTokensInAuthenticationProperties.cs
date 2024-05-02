// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <inheritdoc/>
public class StoreTokensInAuthenticationProperties(
    IOptionsMonitor<UserTokenManagementOptions> tokenManagementOptionsMonitor,
    IOptionsMonitor<CookieAuthenticationOptions> cookieOptionsMonitor,
    IAuthenticationSchemeProvider schemeProvider,
    ILogger<StoreTokensInAuthenticationProperties> logger
) : IStoreTokensInAuthenticationProperties
{
    private const string TokenPrefix = ".Token.";
    private const string TokenNamesKey = ".TokenNames";
    private const string DPoPKeyName = "dpop_proof_key";

    /// Adds the .Token. prefix to the token name and, if the resource
    /// parameter was included, the suffix marking this token as
    /// per-resource.
    private static string NamePrefixAndResourceSuffix(string type, UserTokenRequestParameters? parameters)
    {
        var result = NamePrefix(type);
        if (!string.IsNullOrEmpty(parameters?.Resource))
        {
            result = ResourceSuffix(result, parameters.Resource);
        }
        return result;
    }

    private static string NamePrefix(string name) => $"{TokenPrefix}{name}";

    private static string ResourceSuffix(string name, string resource) => $"{name}::{resource}";

    private static string ChallengeSuffix(string name, string challengeScheme) => $"{name}||{challengeScheme}";

    /// <inheritdoc/>
    public UserToken GetUserToken(AuthenticationProperties authenticationProperties, UserTokenRequestParameters? parameters = null)
    {
        var tokens = authenticationProperties.Items.Where(i => i.Key.StartsWith(TokenPrefix)).ToList();
        if (!tokens.Any())
        {
            logger.LogInformation("No tokens found in cookie properties. SaveTokens must be enabled for automatic token refresh.");

            return new UserToken() { Error = "No tokens in properties" };
        }

        var names = GetTokenNamesWithoutScheme(parameters);

        var appendChallengeScheme = AppendChallengeSchemeToTokenNames(parameters);

        var accessToken = GetTokenValue(tokens, names.Token, appendChallengeScheme, parameters);
        var accessTokenType = GetTokenValue(tokens, names.TokenType, appendChallengeScheme, parameters);
        var dpopKey = GetTokenValue(tokens, names.DPoPKey, appendChallengeScheme, parameters);
        var expiresAt = GetTokenValue(tokens, names.Expires, appendChallengeScheme, parameters);
        var refreshToken = GetTokenValue(tokens, names.RefreshToken, appendChallengeScheme, parameters);

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

    /// <inheritdoc/>
    public async void SetUserToken(
        UserToken token, 
        AuthenticationProperties authenticationProperties,
        UserTokenRequestParameters? parameters = null)
    {
        var tokenNames = GetTokenNamesWithScheme(parameters);

        authenticationProperties.Items[tokenNames.Token] = token.AccessToken;
        authenticationProperties.Items[tokenNames.TokenType] = token.AccessTokenType;
        if (token.DPoPJsonWebKey != null)
        {
            authenticationProperties.Items[tokenNames.DPoPKey] = token.DPoPJsonWebKey;
        }
        authenticationProperties.Items[tokenNames.Expires] = token.Expiration.ToString("o", CultureInfo.InvariantCulture);

        if (token.RefreshToken != null)
        {
            authenticationProperties.Items[tokenNames.RefreshToken] = token.RefreshToken;
        }

        var authenticationScheme = await GetSchemeAsync(parameters);
        var cookieOptions = cookieOptionsMonitor.Get(authenticationScheme);

        if (authenticationProperties.AllowRefresh == true ||
            (authenticationProperties.AllowRefresh == null && cookieOptions.SlidingExpiration))
        {
            // this will allow the cookie to be issued with a new issued (and thus a new expiration)
            authenticationProperties.IssuedUtc = null;
            authenticationProperties.ExpiresUtc = null;
        }

        authenticationProperties.Items.Remove(TokenNamesKey);
        var allTokenNames = authenticationProperties.Items
            .Where(item => item.Key.StartsWith(TokenPrefix))
            .Select(item => item.Key.Substring(TokenPrefix.Length));
        authenticationProperties.Items.Add(new KeyValuePair<string, string?>(TokenNamesKey, string.Join(";", allTokenNames)));
    }

    // If we are using the challenge scheme, we try to get the token 2 ways
    // (with and without the suffix). This is necessary because ASP.NET
    // itself does not set the suffix, so we might not have one at all.
    private static string? GetTokenValue(List<KeyValuePair<string, string?>> tokens, string key, bool appendChallengeScheme, UserTokenRequestParameters? parameters)
    {
        string? token = null;

        if (appendChallengeScheme)
        {
            string scheme = parameters?.ChallengeScheme ?? throw new InvalidOperationException("Attempt to append challenge scheme to token names, but no challenge scheme specified in UserTokenRequestParameters");
            token = tokens.SingleOrDefault(t => t.Key == ChallengeSuffix(key, scheme)).Value;
        }

        if (token.IsMissing())
        {
            token = tokens.SingleOrDefault(t => t.Key == key).Value;
        }

        return token;
    }

    /// <summary>
    /// Confirm application has opted in to UseChallengeSchemeScopedTokens and a
    /// ChallengeScheme is provided upon storage and retrieval of tokens.
    /// </summary>
    /// <param name="parameters"></param>
    /// <returns></returns>
    protected virtual bool AppendChallengeSchemeToTokenNames(UserTokenRequestParameters? parameters)
    {
        return tokenManagementOptionsMonitor.CurrentValue.UseChallengeSchemeScopedTokens && !string.IsNullOrEmpty(parameters?.ChallengeScheme);
    }

    /// <inheritdoc/>
    public async Task<string> GetSchemeAsync(UserTokenRequestParameters? parameters = null)
    {
        return parameters?.SignInScheme ?? 
            (await schemeProvider.GetDefaultSignInSchemeAsync().ConfigureAwait(false))?.Name ??
            throw new InvalidOperationException("No sign in scheme configured");
    }

    /// <inheritdoc/>
    public void RemoveUserToken(AuthenticationProperties authenticationProperties, UserTokenRequestParameters? parameters = null)
    {
        var names = GetTokenNamesWithScheme(parameters);
        authenticationProperties.Items.Remove(names.Token);
        authenticationProperties.Items.Remove(names.TokenType);
        authenticationProperties.Items.Remove(names.Expires);

        // The DPoP key and refresh token are shared with all resources, so we
        // can only delete them if no other tokens with a different resource
        // exist. The key and refresh token are shared for all resources within
        // a challenge scheme if we are using a challenge scheme.

        var keys = authenticationProperties.Items.Keys.Where(k =>
            k.StartsWith(NamePrefix(OpenIdConnectParameterNames.AccessToken)));

        var usingChallengeSuffix = AppendChallengeSchemeToTokenNames(parameters);
        if (usingChallengeSuffix)
        {
            var challengeScheme = parameters?.ChallengeScheme ?? throw new InvalidOperationException("Attempt to use challenge scheme in token names, but no challenge scheme specified in UserTokenRequestParameters");
            var challengeSuffix = $"||{challengeScheme}";
            keys = keys.Where(k => k.EndsWith(challengeSuffix));
        }

        // If we see a resource separator now, we know there are other resources
        // using the refresh token and/or dpop key and so we shouldn't delete
        // them
        var otherResourcesExist = keys.Any(k => k.Contains("::"));

        if(!otherResourcesExist)
        {
            authenticationProperties.Items.Remove(names.DPoPKey);
            authenticationProperties.Items.Remove(names.RefreshToken);
        }
    }

    private TokenNames GetTokenNamesWithoutScheme(UserTokenRequestParameters? parameters = null)
    {
        return new TokenNames
        (
            Token: NamePrefixAndResourceSuffix(OpenIdConnectParameterNames.AccessToken, parameters),
            TokenType: NamePrefixAndResourceSuffix(OpenIdConnectParameterNames.TokenType, parameters),
            Expires: NamePrefixAndResourceSuffix("expires_at", parameters),

            // Note that we are not including the resource suffix because there
            // is no per-resource refresh token or dpop key
            RefreshToken: NamePrefix(OpenIdConnectParameterNames.RefreshToken),
            DPoPKey: NamePrefix(DPoPKeyName)
        );
    }

    private TokenNames GetTokenNamesWithScheme(TokenNames names, UserTokenRequestParameters? parameters = null)
    {
        if (AppendChallengeSchemeToTokenNames(parameters))
        {
             // parameters?.ChallengeScheme should not be null after the call to AppendChallengeSchemeToTokenNames
             // We check for that in the default implementation of AppendChallengeSchemeToTokenNames, but if an override
             // didn't, that's an exception
            string challengeScheme = parameters?.ChallengeScheme ?? throw new InvalidOperationException("Attempt to append challenge scheme to token names, but no challenge scheme specified in UserTokenRequestParameters");
            names = names with
            {
                Token = ChallengeSuffix(names.Token, challengeScheme),
                TokenType = ChallengeSuffix(names.TokenType, challengeScheme),
                DPoPKey = ChallengeSuffix(names.DPoPKey, challengeScheme),
                Expires = ChallengeSuffix(names.Expires, challengeScheme),
                RefreshToken = ChallengeSuffix(names.RefreshToken, challengeScheme)
            }; 
        }
        return names;
    }

    private TokenNames GetTokenNamesWithScheme(UserTokenRequestParameters? parameters = null)
    {
        var names = GetTokenNamesWithoutScheme(parameters);
        return GetTokenNamesWithScheme(names, parameters);
    }
}

record TokenNames(string Token, string TokenType, string DPoPKey, string Expires, string RefreshToken);
