// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using IdentityModel.Client;
using Microsoft.Extensions.Options;

namespace Duende.AccessTokenManagement;

/// <summary>
/// Defines a client credentials client
/// </summary>
public class ClientCredentialsClient
{
    /// <summary>
    /// The address of the OAuth authority. If this is set, the TokenEndpoint
    /// will be set using discovery.
    /// </summary>
    public string? Authority { get; set; }

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

    /// <summary>
    /// The string representation of the JSON web key to use for DPoP.
    /// </summary>
    public string? DPoPJsonWebKey { get; set; }
}


public class ConfigureDiscoveryCache : IPostConfigureOptions<ClientCredentialsClient>
{
    private readonly DiscoveryCaches _discos;
    private readonly HttpClient _httpClient;

    public ConfigureDiscoveryCache(DiscoveryCaches discos, HttpClient httpClient)
    {
        _discos = discos;
        _httpClient = httpClient;
    }


    public void PostConfigure(string name, ClientCredentialsClient options)
    {
        if (options.Authority != null)
        {
            _discos.Set(name, new DiscoveryCache(options.Authority, () => _httpClient)
            {
                CacheDuration = TimeSpan.FromSeconds(10) // FOR TESTING ONLY!
            });
        }
    }
}

public class DiscoveryCaches
{
    private readonly ConcurrentDictionary<string, DiscoveryCache> _discos = new();
    public DiscoveryCache? Get(string name) => _discos.GetValueOrDefault(name);

    internal void Set(string name, DiscoveryCache cache) => _discos[name] = cache;
}

