// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net.Http;
using IdentityModel.Client;

namespace Duende.AccessTokenManagement;

/// <summary>
/// Defines a client credentials client
/// </summary>
public class ClientCredentialsClient
{
    /// <summary>
    /// The address of the token endpoint
    /// </summary>
    public string? TokenEndpoint { get; set; }
    
    /// <summary>
    /// The client ID 
    /// </summary>
    public string? ClientId { get; set; }
    
    /// <summary>
    /// The static (shared) client secret
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// The client credential transmission style
    /// </summary>
    public ClientCredentialStyle ClientCredentialStyle { get; set; }

    /// <summary>
    /// The scope
    /// </summary>
    public string? Scope { get; set; }
    
    /// <summary>
    /// The resource
    /// </summary>
    public string? Resource { get; set; }

    /// <summary>
    /// The HTTP client name to use for the backchannel operations, will fall back to the standard backchannel client if not set
    /// </summary>
    public string? HttpClientName { get; set; }

    /// <summary>
    /// Additional parameters to send with token requests.
    /// </summary>
    public Parameters Parameters { get; set; } = new Parameters();
    
    /// <summary>
    /// The HTTP client instance to use for the back-channel operations, will override the HTTP client name if set
    /// </summary>
    public HttpClient? HttpClient { get; set; }
}