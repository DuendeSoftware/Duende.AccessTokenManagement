// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel.Client;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Duende.TokenManagement.ClientCredentials;
using Microsoft.Extensions.Logging;

namespace Duende.TokenManagement.OpenIdConnect;

/// <summary>
/// Implements token endpoint operations using IdentityModel
/// </summary>
public class UserAccessTokenEndpointService : IUserTokenEndpointService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<UserAccessTokenEndpointService> _logger;
        
    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="httpClientFactory"></param>
    /// <param name="logger"></param>
    public UserAccessTokenEndpointService(
        IHttpClientFactory httpClientFactory,
        ILogger<UserAccessTokenEndpointService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<TokenResponse> RefreshAccessTokenAsync(
        RefreshTokenRequest request,
        CancellationToken cancellationToken = default)
    {
        _logger.LogTrace("Refreshing refresh token: {token}",  request.RefreshToken);
            
        var httpClient = _httpClientFactory.CreateClient(TokenManagementDefaults.BackChannelHttpClientName);
        return await httpClient.RequestRefreshTokenAsync(request, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<TokenRevocationResponse> RevokeRefreshTokenAsync(
        TokenRevocationRequest request, 
        CancellationToken cancellationToken = default)
    {
        _logger.LogTrace("Revoking refresh token: {token}", request.Token);
            
        var httpClient = _httpClientFactory.CreateClient(TokenManagementDefaults.BackChannelHttpClientName);
        return await httpClient.RevokeTokenAsync(request, cancellationToken);
    }
}