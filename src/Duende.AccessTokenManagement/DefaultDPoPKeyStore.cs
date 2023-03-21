// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace Duende.AccessTokenManagement;

/// <summary>
/// Default implementation
/// </summary>
public class DefaultDPoPKeyStore : IDPoPKeyStore
{
    private readonly IOptionsMonitor<ClientCredentialsClient> _options;

    /// <summary>
    /// ctor
    /// </summary>
    public DefaultDPoPKeyStore(IOptionsMonitor<ClientCredentialsClient> options)
    {
        _options = options;
    }

    /// <inheritdoc/>
    public virtual Task<DPoPKey?> GetKeyAsync(string clientName)
    {
        var client = _options.Get(clientName);

        if (string.IsNullOrWhiteSpace(client?.DPoPJsonWebKey))
        {
            return Task.FromResult<DPoPKey?>(null!);
        }

        return Task.FromResult<DPoPKey?>(new DPoPKey { JsonWebKey = client!.DPoPJsonWebKey! });
    }
}
