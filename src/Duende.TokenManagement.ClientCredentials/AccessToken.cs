// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Duende.TokenManagement.ClientCredentials;

/// <summary>
/// Represents a client access token
/// </summary>
public class AccessToken
{
    /// <summary>
    /// The access token
    /// </summary>
    public string? Value { get; set; }
        
    /// <summary>
    /// The access token expiration
    /// </summary>
    public DateTimeOffset? Expiration { get; set; }

    /// <summary>
    /// The scope of the access tokens
    /// </summary>
    public string Scope { get; set; }

    /// <summary>
    /// The resource of the access token
    /// </summary>
    public string Resource { get; set; }
}