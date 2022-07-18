using System.Collections.Concurrent;
using System.Security.Claims;
using Duende.AccessTokenManagement.OpenIdConnect;

namespace BlazorServer.Plumbing;

/// <summary>
/// Simplified implementation of a server-side token store.
/// Probably want somehting more robust IRL
/// </summary>
public class ServerSideTokenStore : IUserTokenStore
{
    private readonly ConcurrentDictionary<string, UserAccessToken> _tokens = new ConcurrentDictionary<string, UserAccessToken>();

    public Task<UserAccessToken> GetTokenAsync(ClaimsPrincipal user, UserAccessTokenRequestParameters? parameters = null)
    {
        var sub = user.FindFirst("sub")?.Value ?? throw new InvalidOperationException("no sub claim");
        
        _tokens.TryGetValue(sub, out var value);
        
        return Task.FromResult(value)!;
    }
    
    public Task StoreTokenAsync(ClaimsPrincipal user, UserAccessToken token, UserAccessTokenRequestParameters? parameters = null)
    {
        var sub = user.FindFirst("sub")?.Value ?? throw new InvalidOperationException("no sub claim");
        _tokens[sub] = token;
        
        return Task.CompletedTask;
    }
    
    public Task ClearTokenAsync(ClaimsPrincipal user, UserAccessTokenRequestParameters? parameters = null)
    {
        var sub = user.FindFirst("sub")?.Value ?? throw new InvalidOperationException("no sub claim");
        
        _tokens.TryRemove(sub, out _);
        return Task.CompletedTask;
    }
}