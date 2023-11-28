using Microsoft.Extensions.Caching.Distributed;

namespace Duende.AccessTokenManagement.Tests;

internal class TestDistributedCache : IDistributedCache
{
    private readonly Dictionary<string, byte[]?> _cache = new();
    
    public byte[]? Get(string key)
    {
        return _cache[key];
    }

    public Task<byte[]?> GetAsync(string key, CancellationToken token = new CancellationToken())
    {
        return Task.FromResult(_cache[key]);
    }

    public void Refresh(string key)
    {
    }

    public Task RefreshAsync(string key, CancellationToken token = new CancellationToken())
    {
        Refresh(key);
        return Task.CompletedTask;
    }

    public void Remove(string key)
    {
        _cache.Remove(key);
    }

    public Task RemoveAsync(string key, CancellationToken token = new CancellationToken())
    {
        Remove(key);
        return Task.CompletedTask;
    }

    public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
    {
        _cache.Add(key, value);
    }

    public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options,
        CancellationToken token = new CancellationToken())
    {
        Set(key, value, options);
        return Task.CompletedTask;
    }
}