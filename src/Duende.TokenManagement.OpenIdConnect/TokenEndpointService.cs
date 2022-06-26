// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using IdentityModel.Client;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Duende.TokenManagement.ClientCredentials;
using IdentityModel;
using Microsoft.Extensions.Logging;

namespace Duende.TokenManagement.OpenIdConnect
{
    /// <summary>
    /// Implements token endpoint operations using IdentityModel
    /// </summary>
    public class UserTokenEndpointService : IUserTokenEndpointService
    {
        private readonly IUserTokenConfigurationService _configService;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<UserTokenEndpointService> _logger;
        
        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="configService"></param>
        /// <param name="httpClientFactory"></param>
        /// <param name="logger"></param>
        public UserTokenEndpointService(
            IUserTokenConfigurationService configService,
            IHttpClientFactory httpClientFactory,
            ILogger<UserTokenEndpointService> logger)
        {
            _configService = configService;
            _httpClientFactory = httpClientFactory;
            _logger = logger;
        }

        /// <inheritdoc/>
        public async Task<TokenResponse> RefreshAccessTokenAsync(
            string refreshToken, 
            UserAccessTokenParameters? parameters = null, 
            CancellationToken cancellationToken = default)
        {
            _logger.LogDebug("Refreshing refresh token: {token}", refreshToken);
            
            parameters ??= new UserAccessTokenParameters();
            
            var requestDetails = await _configService.GetRefreshTokenRequestAsync(parameters);
            requestDetails.RefreshToken = refreshToken;
            

            requestDetails.Options.TryAdd(TokenManagementDefaults.AccessTokenParametersOptionsName, parameters);

            
            if (!string.IsNullOrEmpty(parameters.Resource))
            {
                requestDetails.Resource.Add(parameters.Resource);
            }

            var httpClient = _httpClientFactory.CreateClient(TokenManagementDefaults.BackChannelHttpClientName);
            return await httpClient.RequestRefreshTokenAsync(requestDetails, cancellationToken);
        }

        /// <inheritdoc/>
        public async Task<TokenRevocationResponse> RevokeRefreshTokenAsync(
            string refreshToken, 
            UserAccessTokenParameters? parameters = null, 
            CancellationToken cancellationToken = default)
        {
            _logger.LogDebug("Revoking refresh token: {token}", refreshToken);
            
            parameters ??= new UserAccessTokenParameters();
            
            var requestDetails = await _configService.GetTokenRevocationRequestAsync(parameters);
            requestDetails.Token = refreshToken;
            requestDetails.TokenTypeHint = OidcConstants.TokenTypes.RefreshToken;
            
            requestDetails.Options.TryAdd(TokenManagementDefaults.AccessTokenParametersOptionsName, parameters);
            
            var httpClient = _httpClientFactory.CreateClient(TokenManagementDefaults.BackChannelHttpClientName);
            return await httpClient.RevokeTokenAsync(requestDetails, cancellationToken);
        }
    }
}