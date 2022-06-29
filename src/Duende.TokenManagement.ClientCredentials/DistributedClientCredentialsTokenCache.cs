// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Duende.TokenManagement.ClientCredentials;

/// <summary>
/// Client access token cache using IDistributedCache
/// </summary>
public class DistributedClientCredentialsTokenCache : IClientCredentialsTokenCache
{
    private readonly IDistributedCache _cache;
    private readonly ILogger<DistributedClientCredentialsTokenCache> _logger;
    private readonly ClientCredentialsTokenManagementOptions _options;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="cache"></param>
    /// <param name="options"></param>
    /// <param name="logger"></param>
    public DistributedClientCredentialsTokenCache(IDistributedCache cache, IOptions<ClientCredentialsTokenManagementOptions> options, ILogger<DistributedClientCredentialsTokenCache> logger)
    {
        _cache = cache;
        _logger = logger;
        _options = options.Value;
    }
        
    /// <inheritdoc/>
    public async Task SetAsync(
        string clientName,
        ClientCredentialsAccessToken clientCredentialsAccessToken,
        AccessTokenRequestParameters requestParameters,
        CancellationToken cancellationToken = default)
    {
        if (clientName is null) throw new ArgumentNullException(nameof(clientName));
            
        // if the token service does not return expiresIn, cache forever and wait for 401
        var expiration = DateTimeOffset.MaxValue;
        if (clientCredentialsAccessToken.Expiration.HasValue)
        {
            expiration = clientCredentialsAccessToken.Expiration.Value;
        }
        
        var cacheExpiration = expiration.AddSeconds(-_options.CacheLifetimeBuffer);
        var data = JsonSerializer.Serialize(clientCredentialsAccessToken);

        var entryOptions = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = cacheExpiration
        };

        _logger.LogDebug("Caching access token for client: {clientName}. Expiration: {expiration}", clientName, cacheExpiration);
            
        var cacheKey = GenerateCacheKey(_options, clientName, requestParameters);
        await _cache.SetStringAsync(cacheKey, data, entryOptions, token: cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<ClientCredentialsAccessToken?> GetAsync(
        string clientName, 
        AccessTokenRequestParameters requestParameters,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(clientName);
            
        var cacheKey = GenerateCacheKey(_options, clientName, requestParameters);
        var entry = await _cache.GetStringAsync(cacheKey, token: cancellationToken);

        if (entry != null)
        {
            try
            {
                _logger.LogDebug("Cache hit for access token for client: {clientName}", clientName);
                return JsonSerializer.Deserialize<ClientCredentialsAccessToken>(entry);
            }
            catch (Exception ex)
            {
                _logger.LogCritical(ex, "Error parsing cached access token for client {clientName}", clientName);
                return null;
            }
        }

        _logger.LogDebug("Cache miss for access token for client: {clientName}", clientName);
        return null;
    }

    /// <inheritdoc/>
    public Task DeleteAsync(
        string clientName,
        AccessTokenRequestParameters requestParameters,
        CancellationToken cancellationToken = default)
    {
        if (clientName is null) throw new ArgumentNullException(nameof(clientName));

        var cacheKey = GenerateCacheKey(_options, clientName, requestParameters);
        return _cache.RemoveAsync(cacheKey, cancellationToken);
    }

    /// <summary>
    /// Generates the cache key based on various inputs
    /// </summary>
    /// <param name="options"></param>
    /// <param name="clientName"></param>
    /// <param name="parameters"></param>
    /// <returns></returns>
    protected virtual string GenerateCacheKey(
        ClientCredentialsTokenManagementOptions options, 
        string clientName,
        AccessTokenRequestParameters? parameters = null)
    {
        return options.CacheKeyPrefix + "::" + clientName + "::" + parameters?.Resource ?? "";
    }
}