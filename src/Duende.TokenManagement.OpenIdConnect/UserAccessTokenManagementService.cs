using System;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Duende.TokenManagement.ClientCredentials;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Duende.TokenManagement.OpenIdConnect;

/// <summary>
/// Implements basic token management logic
/// </summary>
public class UserAccessAccessTokenManagementService : IUserTokenManagementService
{
    private readonly IUserAccessTokenRequestSynchronization _sync;
    private readonly IUserTokenStore _userAccessTokenStore;
    private readonly ISystemClock _clock;
    private readonly UserAccessTokenManagementOptions _options;
    private readonly IUserTokenEndpointService _tokenEndpointService;
    private readonly ILogger<UserAccessAccessTokenManagementService> _logger;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="sync"></param>
    /// <param name="userAccessTokenStore"></param>
    /// <param name="clock"></param>
    /// <param name="options"></param>
    /// <param name="tokenEndpointService"></param>
    /// <param name="clientCredentialsTokenManagementService"></param>
    /// <param name="logger"></param>
    public UserAccessAccessTokenManagementService(
        IUserAccessTokenRequestSynchronization sync,
        IUserTokenStore userAccessTokenStore,
        ISystemClock clock,
        IOptions<UserAccessTokenManagementOptions> options,
        IUserTokenEndpointService tokenEndpointService,
        IClientCredentialsTokenManagementService clientCredentialsTokenManagementService,
        ILogger<UserAccessAccessTokenManagementService> logger)
    {
        _sync = sync;
        _userAccessTokenStore = userAccessTokenStore;
        _clock = clock;
        _options = options.Value;
        _tokenEndpointService = tokenEndpointService;
        _logger = logger;
    }
        
    /// <inheritdoc/>
    public async Task<UserAccessToken> GetAccessTokenAsync(
        ClaimsPrincipal user, 
        UserAccessTokenRequestParameters? parameters = null, 
        CancellationToken cancellationToken = default)
    {
        _logger.LogTrace("Starting user token acquisition");
            
        parameters ??= new UserAccessTokenRequestParameters();
            
        if (!user.Identity!.IsAuthenticated)
        {
            _logger.LogDebug("No active user. Cannot retrieve token");
            return new UserAccessToken();
        }

        var userName = user.FindFirst(JwtClaimTypes.Name)?.Value ?? user.FindFirst(JwtClaimTypes.Subject)?.Value ?? "unknown";
        var userToken = await _userAccessTokenStore.GetTokenAsync(user, parameters);
            
        if (userToken.Value.IsMissing() && userToken.RefreshToken.IsMissing())
        {
            _logger.LogDebug("No token data found in user token store for user {user}.", userName);
            return new UserAccessToken();
        }
            
        if (userToken.Value.IsPresent() && userToken.RefreshToken.IsMissing())
        {
            _logger.LogDebug("No refresh token found in user token store for user {user} / resource {resource}. Returning current access token.", userName, parameters.Resource ?? "default");
            return userToken;
        }

        if (userToken.Value.IsMissing() && userToken.RefreshToken.IsPresent())
        {
            _logger.LogDebug(
                "No access token found in user token store for user {user} / resource {resource}. Trying to refresh.",
                userName, parameters.Resource ?? "default");
        }

        var dtRefresh = userToken.Expiration.Subtract(_options.RefreshBeforeExpiration);
        if (dtRefresh < _clock.UtcNow || parameters.ForceRenewal)
        {
            _logger.LogDebug("Token for user {user} needs refreshing.", userName);

            try
            {
                return await _sync.Dictionary.GetOrAdd(userToken.RefreshToken!, _ =>
                {
                    return new Lazy<Task<UserAccessToken>>(async () =>
                    {
                        var token = await RefreshUserAccessTokenAsync(user, parameters, cancellationToken);

                        _logger.LogTrace("Returning refreshed token for user: {user}", userName);
                        return token;
                    });
                }).Value;
            }
            finally
            {
                _sync.Dictionary.TryRemove(userToken.RefreshToken!, out _);
            }
        }

        _logger.LogTrace("Returning current token for user: {user}", userName);
        return userToken;
    }

    /// <inheritdoc/>
    public async Task RevokeRefreshTokenAsync(
        ClaimsPrincipal user, 
        UserAccessTokenRequestParameters? parameters = null, 
        CancellationToken cancellationToken = default)
    {
        parameters ??= new UserAccessTokenRequestParameters();
        var userToken = await _userAccessTokenStore.GetTokenAsync(user, parameters);

        if (!string.IsNullOrWhiteSpace(userToken.RefreshToken))
        {
            await _tokenEndpointService.RevokeRefreshTokenAsync(userToken.RefreshToken, parameters, cancellationToken);    
        }
    }
    
    private async Task<UserAccessToken> RefreshUserAccessTokenAsync(
        ClaimsPrincipal user,
        UserAccessTokenRequestParameters parameters,
        CancellationToken cancellationToken = default)
    {
        var userToken = await _userAccessTokenStore.GetTokenAsync(user, parameters);
        
        // todo: should not happen - should we use better exception?
        ArgumentNullException.ThrowIfNull(userToken.RefreshToken);
        
        var refreshedToken = await _tokenEndpointService.RefreshAccessTokenAsync(userToken.RefreshToken, parameters, cancellationToken);
        if (refreshedToken.IsError)
        {
            _logger.LogError("Error refreshing access token. Error = {error}", refreshedToken.Error);
        }
        else
        {
            await _userAccessTokenStore.StoreTokenAsync(user, refreshedToken, parameters);
        }

        return refreshedToken;
    }
}