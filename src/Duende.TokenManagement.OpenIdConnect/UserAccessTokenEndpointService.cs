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
using Microsoft.Extensions.Options;

namespace Duende.TokenManagement.OpenIdConnect;

/// <summary>
/// Implements token endpoint operations using IdentityModel
/// </summary>
public class UserAccessTokenEndpointService : IUserTokenEndpointService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IOpenIdConnectConfigurationService _configurationService;
    private readonly ILogger<UserAccessTokenEndpointService> _logger;
    private readonly UserAccessTokenManagementOptions _options;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="httpClientFactory"></param>
    /// <param name="options"></param>
    /// <param name="logger"></param>
    /// <param name="configurationService"></param>
    public UserAccessTokenEndpointService(
        IHttpClientFactory httpClientFactory,
        IOpenIdConnectConfigurationService configurationService,
        IOptions<UserAccessTokenManagementOptions> options,
        ILogger<UserAccessTokenEndpointService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _configurationService = configurationService;
        _options = options.Value;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<UserAccessToken> RefreshAccessTokenAsync(
        string refreshToken,
        UserAccessTokenRequestParameters parameters,
        CancellationToken cancellationToken = default)
    {
        _logger.LogTrace("Refreshing refresh token: {token}",  refreshToken);

        var oidc = await _configurationService.GetOpenIdConnectConfigurationAsync(parameters.ChallengeScheme);

        var request = new RefreshTokenRequest
        {
            Address = oidc.TokenEndpoint,
            
            ClientId = oidc.ClientId,
            ClientSecret = oidc.ClientSecret,
            ClientCredentialStyle = _options.ClientCredentialStyle,
            
            RefreshToken = refreshToken
        };
        
        request.Options.TryAdd(TokenManagementDefaults.AccessTokenParametersOptionsName, parameters);
        
        if (!string.IsNullOrEmpty(parameters.Resource))
        {
            request.Resource.Add(parameters.Resource);
        }

        await ApplyAssertionAsync(request, parameters);
            
        var httpClient = _httpClientFactory.CreateClient(OpenIdConnectTokenManagementDefaults.BackChannelHttpClientName);
        var response = await httpClient.RequestRefreshTokenAsync(request, cancellationToken);

        var token = new UserAccessToken();
        if (response.IsError)
        {
            token.Error = response.Error;
        }
        else
        {
            token.Value = response.AccessToken;
            token.Expiration = response.ExpiresIn == 0
                ? DateTimeOffset.MaxValue
                : DateTimeOffset.UtcNow.AddSeconds(response.ExpiresIn);
            token.RefreshToken = response.RefreshToken;
            token.Scope = response.Scope;    
        }

        return token;
    }

    /// <inheritdoc/>
    public async Task RevokeRefreshTokenAsync(
        string refreshToken,
        UserAccessTokenRequestParameters parameters,
        CancellationToken cancellationToken = default)
    {
        _logger.LogTrace("Revoking refresh token: {token}", refreshToken);
        
        var oidc = await _configurationService.GetOpenIdConnectConfigurationAsync(parameters.ChallengeScheme);

        var request = new TokenRevocationRequest
        {
            Address = oidc.RevocationEndpoint,
            
            ClientId = oidc.ClientId,
            ClientSecret = oidc.ClientSecret,
            ClientCredentialStyle = _options.ClientCredentialStyle,
            
            Token = refreshToken,
            TokenTypeHint = OidcConstants.TokenTypes.RefreshToken
        };
        
        request.Options.TryAdd(TokenManagementDefaults.AccessTokenParametersOptionsName, parameters);
       
        await ApplyAssertionAsync(request, parameters);
        
        var httpClient = _httpClientFactory.CreateClient(OpenIdConnectTokenManagementDefaults.BackChannelHttpClientName);
        var response = await httpClient.RevokeTokenAsync(request, cancellationToken);
        
        _logger.LogInformation("Error revoking refresh token. Error = {error}", response.Error);
    }
    
    private async Task ApplyAssertionAsync(ProtocolRequest request, ClientCredentialsTokenRequestParameters parameters)
    {
        if (parameters.Assertion != null)
        {
            request.ClientAssertion = parameters.Assertion;
        }
        else
        {
            var assertion = await CreateAssertionAsync();
            if (assertion != null)
            {
                request.ClientCredentialStyle = ClientCredentialStyle.PostBody;
                request.ClientAssertion = assertion;
            }    
        }
    }

    /// <summary>
    /// Allows injecting a client assertion into outgoing requests
    /// </summary>
    /// <param name="clientName">Name of client (if present)</param>
    /// <returns></returns>
    protected virtual Task<ClientAssertion?> CreateAssertionAsync(string? clientName = null)
    {
        return Task.FromResult<ClientAssertion?>(null);
    }
}