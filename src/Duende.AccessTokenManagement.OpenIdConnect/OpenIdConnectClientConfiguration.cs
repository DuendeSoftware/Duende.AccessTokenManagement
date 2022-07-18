// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net.Http;

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <summary>
/// Configuration setting sourced from the OpenID Connect handler
/// </summary>
public class OpenIdConnectClientConfiguration
{
    /// <summary>
    /// The authority
    /// </summary>
    public string? Authority { get; set; }
    
    /// <summary>
    /// The token endpoint address
    /// </summary>
    public string? TokenEndpoint { get; set; }

    /// <summary>
    /// The revocation endpoint address
    /// </summary>
    public string? RevocationEndpoint { get; set; }

    /// <summary>
    /// The client ID
    /// </summary>
    public string? ClientId { get; set; }
    
    /// <summary>
    /// The client secret
    /// </summary>
    public string? ClientSecret { get; set; }
    
    /// <summary>
    /// The HTTP client associated with the OIDC handler (if based on scheme configuration)
    /// </summary>
    public HttpClient? HttpClient { get; set; }
    
    /// <summary>
    /// The scheme name of the OIDC handler
    /// </summary>
    public string? Scheme { get; set; }
}