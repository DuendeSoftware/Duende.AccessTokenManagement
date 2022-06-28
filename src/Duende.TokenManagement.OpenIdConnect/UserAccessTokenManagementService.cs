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
    private readonly ITokenRequestSynchronization _sync;
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
        ITokenRequestSynchronization sync,
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

        var dtRefresh = DateTimeOffset.MinValue;
        if (userToken.Expiration.HasValue)
        {
            dtRefresh = userToken.Expiration.Value.Subtract(_options.RefreshBeforeExpiration);
        }
            
        if (dtRefresh < _clock.UtcNow || parameters.ForceRenewal)
        {
            _logger.LogDebug("Token for user {user} needs refreshing.", userName);

            try
            {
                return await _sync.Dictionary.GetOrAdd(userToken.RefreshToken!, _ =>
                {
                    return new Lazy<Task<UserAccessToken>>(async () =>
                    {
                        var refreshed = await RefreshUserAccessTokenAsync(user, parameters, cancellationToken);

                        var token = new UserAccessToken
                        {
                            Value = refreshed.AccessToken,
                            Expiration = DateTimeOffset.UtcNow.AddSeconds(refreshed.ExpiresIn),
                            RefreshToken = refreshed.RefreshToken,
                            Scope = refreshed.Scope,
                            Resource = refreshed.TryGet("resource")
                        };

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

    private async Task<TokenResponse> RefreshUserAccessTokenAsync(
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
            // todo: what to do if expires_in is missing?
            var expiration = DateTime.UtcNow + TimeSpan.FromSeconds(response.ExpiresIn);

            var token = new UserAccessToken
            {
                Value = response.AccessToken,
                Expiration = expiration,
                RefreshToken = response.RefreshToken,
                Scope = response.Scope,
                Resource = response.TryGet("resource")
            };

            await _userAccessTokenStore.StoreTokenAsync(user, token, parameters);
        }
        else
        {
            _logger.LogError("Error refreshing access token. Error = {error}", response.Error);
        }

        return response;
    }

    public async Task<AccessToken> GetClientCredentialAccessTokenAsync(
        AccessTokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        parameters ??= new AccessTokenRequestParameters();

        var request = await _userTokenConfigurationService.GetClientCredentialsRequestAsync();
        
        return await _clientCredentialsTokenManagementService.GetAccessTokenAsync(
            "oidc", 
            request: request,
            parameters: parameters,
            cancellationToken: cancellationToken);
    }
}