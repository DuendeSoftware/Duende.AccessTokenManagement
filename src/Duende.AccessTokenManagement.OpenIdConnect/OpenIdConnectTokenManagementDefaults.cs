// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <summary>
/// Default values
/// </summary>
public static class OpenIdConnectTokenManagementDefaults
{
    /// <summary>
    /// Prefix to use for registering scheme based client credentials client in options system on the fly
    /// </summary>
    public const string ClientCredentialsClientNamePrefix = "Duende.TokenManagement.SchemeBasedClient:";
}