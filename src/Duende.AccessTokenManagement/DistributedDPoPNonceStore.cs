// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;

namespace Duende.AccessTokenManagement;

/// <summary>
/// DPoP nonce store using IDistributedCache
/// </summary>
public class DistributedDPoPNonceStore : IDPoPNonceStore
{
    const string CacheKeyPrefix = "DistributedDPoPNonceStore";
    const char CacheKeySeparator = ':';

    private readonly IDistributedCache _cache;
    private readonly ILogger<DistributedDPoPNonceStore> _logger;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="cache"></param>
    /// <param name="logger"></param>
    public DistributedDPoPNonceStore(
        IDistributedCache cache, 
        ILogger<DistributedDPoPNonceStore> logger)
    {
        _cache = cache;
        _logger = logger;
    }
        
    /// <inheritdoc/>
    public virtual async Task<string?> GetNonceAsync(DPoPNonceContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var cacheKey = GenerateCacheKey(context);
        var entry = await _cache.GetStringAsync(cacheKey, token: cancellationToken).ConfigureAwait(false);

        if (entry != null)
        {
            _logger.LogDebug("Cache hit for DPoP nonce for URL: {url}, method: {method}", context.Url, context.Method);
            return entry;
        }

        _logger.LogTrace("Cache miss for DPoP nonce for URL: {url}, method: {method}", context.Url, context.Method);
        return null;
    }

    /// <inheritdoc/>
    public virtual async Task StoreNonceAsync(DPoPNonceContext context, string nonce, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var cacheExpiration = DateTimeOffset.UtcNow.AddHours(1);
        var data = nonce;

        var entryOptions = new DistributedCacheEntryOptions
        {
            AbsoluteExpiration = cacheExpiration
        };

        _logger.LogTrace("Caching DPoP nonce for URL: {url}, method: {method}. Expiration: {expiration}", context.Url, context.Method, cacheExpiration);

        var cacheKey = GenerateCacheKey(context);
        await _cache.SetStringAsync(cacheKey, data, entryOptions, token: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Generates the cache key based on various inputs
    /// </summary>
    protected virtual string GenerateCacheKey(DPoPNonceContext context)
    {
        return $"{CacheKeyPrefix}{CacheKeySeparator}{context.Url}{CacheKeySeparator}{context.Method}";
    }
}