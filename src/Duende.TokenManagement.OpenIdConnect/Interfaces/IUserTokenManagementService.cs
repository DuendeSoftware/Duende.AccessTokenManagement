using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Duende.TokenManagement.OpenIdConnect;

/// <summary>
/// Abstraction for managing user access tokens
/// </summary>
public interface IUserTokenManagementService
{
    /// <summary>
    /// Returns the user access token. If the current token is expired, it will try to refresh it.
    /// </summary>
    /// <param name="user"></param>
    /// <param name="parameters"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<UserAccessToken> GetAccessTokenAsync(
        ClaimsPrincipal user, 
        UserAccessTokenRequestParameters? parameters = null, 
        CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Revokes the current refresh token
    /// </summary>
    /// <param name="user"></param>
    /// <param name="parameters"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task RevokeRefreshTokenAsync(
        ClaimsPrincipal user, 
        UserAccessTokenRequestParameters? parameters = null, 
        CancellationToken cancellationToken = default);
}