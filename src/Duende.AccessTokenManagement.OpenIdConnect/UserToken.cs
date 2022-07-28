// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <summary>
/// Models a user access token
/// </summary>
public class UserToken : ClientCredentialsToken
{
    /// <summary>
    /// The refresh token
    /// </summary>
    public string? RefreshToken { get; set; }
}