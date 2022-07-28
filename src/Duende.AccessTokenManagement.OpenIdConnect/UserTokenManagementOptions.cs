// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using IdentityModel.Client;

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <summary>
/// Options for user access token management
/// </summary>
public class UserTokenManagementOptions
{
    /// <summary>
    /// Name of the authentication scheme to use for deriving token service configuration
    /// (will fall back to configured default challenge scheme if not set)
    /// </summary>
    public string? ChallengeScheme { get; set; }
    
    /// <summary>
    /// Boolean to set whether tokens added to a session should be challenge-scheme-specific.
    /// The default is 'false'.
    /// </summary>
    public bool UseChallengeSchemeScopedTokens { get; set; }

    /// <summary>
    /// Timespan that specifies how long before expiration, the token should be refreshed (defaults to 1 minute)
    /// </summary>
    public TimeSpan RefreshBeforeExpiration { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Scope value when requesting a client credentials token.
    /// If not set, token request will omit scope parameter.
    /// </summary>
    public string? ClientCredentialsScope { get; set; }

    /// <summary>
    /// Resource value when requesting a client credentials token.
    /// If not set, token request will omit resource parameter.
    /// </summary>
    public string? ClientCredentialsResource { get; set; }

    /// <summary>
    /// Default client credential style to use when requesting tokens
    /// </summary>
    public ClientCredentialStyle ClientCredentialStyle { get; set; } = ClientCredentialStyle.AuthorizationHeader;
    // TODO: should we make this same as the AspNet OIDC handler (which defaults to the form body)
}