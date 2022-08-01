// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <summary>
/// Additional optional per request parameters for a user access token request
/// </summary>
public class UserTokenRequestParameters : TokenRequestParameters
{
    /// <summary>
    /// Overrides the default sign-in scheme. This information may be used for state management.
    /// </summary>
    public string? SignInScheme { get; set; }
        
    /// <summary>
    /// Overrides the default challenge scheme. This information may be used for deriving token service configuration.
    /// </summary>
    public string? ChallengeScheme { get; set; }
}