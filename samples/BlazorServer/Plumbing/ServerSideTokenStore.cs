using System.Collections.Concurrent;
using System.Security.Claims;
using Duende.TokenManagement.OpenIdConnect;

namespace BlazorServer.Plumbing;

/// <summary>
/// Simplified implementation of a server-side token store.
/// Probably want somehting more robust IRL
/// </summary>
public class ServerSideTokenStore : IUserTokenStore
{
    private readonly ConcurrentDictionary<string, UserAccessToken> _tokens = new();

    public Task StoreTokenAsync(ClaimsPrincipal user, UserAccessToken token, UserAccessTokenRequestParameters? parameters = null)
    {
        var sub = user.FindFirst("sub")?.Value ?? throw new InvalidOperationException("no sub claim");
        
        _tokens[sub] = token;
        
        return Task.CompletedTask;
    }

    public Task<UserAccessToken> GetTokenAsync(ClaimsPrincipal user, UserAccessTokenRequestParameters? parameters = null)
    {
        var sub = user.FindFirst("sub")?.Value ?? throw new InvalidOperationException("no sub claim");
        
        if (_tokens.TryGetValue(sub, out var value))
        {
            return Task.FromResult(value);
        }

        return Task.FromResult(new UserAccessToken());
    }

    public Task ClearTokenAsync(ClaimsPrincipal user, UserAccessTokenRequestParameters? parameters = null)
    {
        var sub = user.FindFirst("sub")?.Value ?? throw new InvalidOperationException("no sub claim");
        
        _tokens.TryRemove(sub, out _);
        return Task.CompletedTask;
    }
}