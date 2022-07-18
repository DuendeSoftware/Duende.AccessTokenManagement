// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel.Client;

namespace Duende.AccessTokenManagement.ClientCredentials;

/// <summary>
/// Additional optional parameters for a client credentials access token request
/// </summary>
public class ClientCredentialsTokenRequestParameters
{
    /// <summary>
    /// Force renewal of token.
    /// </summary>
    public bool ForceRenewal { get; set; }

    /// <summary>
    /// Override the statically configured scope parameter.
    /// </summary>
    public string? Scope { get; set; }
    
    /// <summary>
    /// Override the statically configured resource parameter.
    /// </summary>
    public string? Resource { get; set; }
    
    /// <summary>
    /// Specifies the client assertion.
    /// </summary>
    public ClientAssertion? Assertion { get; set; }

    /// <summary>
    /// Additional context that might be relevant in the pipeline
    /// </summary>
    public Parameters Context { get; set; } = new();
}