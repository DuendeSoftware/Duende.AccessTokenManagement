using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Duende.TokenManagement.ClientCredentials;
using IdentityModel;
using IdentityModel.Client;
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
    private readonly IUserTokenConfigurationService _userTokenConfigurationService;
    private readonly IUserTokenEndpointService _tokenEndpointService;
    private readonly IClientCredentialsTokenManagementService _clientCredentialsTokenManagementService;
    private readonly ILogger<UserAccessAccessTokenManagementService> _logger;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="sync"></param>
    /// <param name="userAccessTokenStore"></param>
    /// <param name="clock"></param>
    /// <param name="options"></param>
    /// <param name="userTokenConfigurationService"></param>
    /// <param name="tokenEndpointService"></param>
    /// <param name="clientCredentialsTokenManagementService"></param>
    /// <param name="logger"></param>
    public UserAccessAccessTokenManagementService(
        IUserAccessTokenRequestSynchronization sync,
        IUserTokenStore userAccessTokenStore,
        ISystemClock clock,
        IOptions<UserAccessTokenManagementOptions> options,
        IUserTokenConfigurationService userTokenConfigurationService,
        IUserTokenEndpointService tokenEndpointService,
        IClientCredentialsTokenManagementService clientCredentialsTokenManagementService,
        ILogger<UserAccessAccessTokenManagementService> logger)
    {
        _sync = sync;
        _userAccessTokenStore = userAccessTokenStore;
        _clock = clock;
        _options = options.Value;
        _userTokenConfigurationService = userTokenConfigurationService;
        _tokenEndpointService = tokenEndpointService;
        _clientCredentialsTokenManagementService = clientCredentialsTokenManagementService;
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
        var requestDetails = await _userTokenConfigurationService.GetTokenRevocationRequestAsync(parameters);
            
        requestDetails.Token = userToken.RefreshToken;
        requestDetails.TokenTypeHint = OidcConstants.TokenTypes.RefreshToken;
        requestDetails.Options.TryAdd(TokenManagementDefaults.AccessTokenParametersOptionsName, parameters);
            
        if (!string.IsNullOrEmpty(userToken?.RefreshToken))
        {
            var response = await _tokenEndpointService.RevokeRefreshTokenAsync(requestDetails, cancellationToken);

            if (response.IsError)
            {
                _logger.LogError("Error revoking refresh token. Error = {error}", response.Error);
            }
        }
    }
    
    /// <inheritdoc/>
    public async Task<ClientCredentialsAccessToken> GetClientCredentialAccessTokenAsync(
        ClientCredentialsTokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        parameters ??= new ClientCredentialsTokenRequestParameters();

        var request = await _userTokenConfigurationService.GetClientCredentialsRequestAsync(parameters);
        
        return await _clientCredentialsTokenManagementService.GetAccessTokenAsync(
            "oidc", 
            request: request,
            parameters: parameters,
            cancellationToken: cancellationToken);
    }

    private async Task<UserAccessToken> RefreshUserAccessTokenAsync(
        ClaimsPrincipal user,
        UserAccessTokenRequestParameters parameters,
        CancellationToken cancellationToken = default)
    {
        var userToken = await _userAccessTokenStore.GetTokenAsync(user, parameters);
        var requestDetails = await _userTokenConfigurationService.GetRefreshTokenRequestAsync(parameters);
            
        requestDetails.RefreshToken = userToken.RefreshToken;
        requestDetails.Options.TryAdd(TokenManagementDefaults.AccessTokenParametersOptionsName, parameters);

        var response = await _tokenEndpointService.RefreshAccessTokenAsync(requestDetails, cancellationToken);

        if (!response.IsError)
        {
            var token = new UserAccessToken
            {
                Value = response.AccessToken,
                Expiration = response.ExpiresIn == 0
                    ? DateTimeOffset.MaxValue
                    : DateTimeOffset.UtcNow.AddSeconds(response.ExpiresIn),
                RefreshToken = response.RefreshToken,
                Scope = response.Scope
            };

            await _userAccessTokenStore.StoreTokenAsync(user, token, parameters);
            return token;
        }

        _logger.LogError("Error refreshing access token. Error = {error}", response.Error);
        return new UserAccessToken();
    }
}