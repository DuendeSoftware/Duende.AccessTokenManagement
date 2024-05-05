using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using IdentityModel.Client;

namespace Duende.AccessTokenManagement;

/// <inheritdoc/>
public class TokenEndpointRetriever : ITokenEndpointRetriever
{
    private readonly Dictionary<string, DiscoveryCache> _caches = new();

    private DiscoveryCache GetDiscoCache(string authority)
    {
        if (!_caches.ContainsKey(authority))
        {
            _caches[authority] = new DiscoveryCache(authority);
        }
        return _caches[authority];
    }

    /// <inheritdoc/>
    public async Task<string> GetAsync(ClientCredentialsClient client)
    {
        if (client.Authority.IsPresent())
        {
            var discoCache = GetDiscoCache(client.Authority);
            var disco = await discoCache.GetAsync();
            if(disco.IsError)
            {
                throw new InvalidOperationException("Failed to retrieve disco");
            }
            return disco.TokenEndpoint ?? throw new InvalidOperationException("Disco does not contain token endpoint");
        }
        else if (client.TokenEndpoint.IsPresent())
        {
            return client.TokenEndpoint;
        }
        else
        {
            throw new InvalidOperationException("No token endpoint or authority configured");
        }

    }
}