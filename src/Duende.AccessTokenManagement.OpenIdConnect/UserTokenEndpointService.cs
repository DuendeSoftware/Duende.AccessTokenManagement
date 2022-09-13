// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using IdentityModel.Client;
using System.Threading;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <summary>
/// Implements token endpoint operations using IdentityModel
/// </summary>
public class UserTokenEndpointService : IUserTokenEndpointService
{
    private readonly IOpenIdConnectConfigurationService _configurationService;
    private readonly IClientAssertionService _clientAssertionService;
    private readonly ILogger<UserTokenEndpointService> _logger;
    private readonly UserTokenManagementOptions _options;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="options"></param>
    /// <param name="clientAssertionService"></param>
    /// <param name="logger"></param>
    /// <param name="configurationService"></param>
    public UserTokenEndpointService(
        IOpenIdConnectConfigurationService configurationService,
        IOptions<UserTokenManagementOptions> options,
        IClientAssertionService clientAssertionService,
        ILogger<UserTokenEndpointService> logger)
    {
        _configurationService = configurationService;
        _clientAssertionService = clientAssertionService;
        _options = options.Value;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<UserToken> RefreshAccessTokenAsync(
        string refreshToken,
        UserTokenRequestParameters parameters,
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
        
        request.Options.TryAdd(ClientCredentialsTokenManagementDefaults.TokenRequestParametersOptionsName, parameters);
        
        if (!string.IsNullOrEmpty(parameters.Resource))
        {
            request.Resource.Add(parameters.Resource);
        }
        
        if (parameters.Assertion != null)
        {
            request.ClientAssertion = parameters.Assertion;
            request.ClientCredentialStyle = ClientCredentialStyle.PostBody;
        }
        else
        {
            var assertion = await _clientAssertionService.GetClientAssertionAsync(OpenIdConnectTokenManagementDefaults.ClientCredentialsClientNamePrefix + oidc.Scheme, parameters);
            if (assertion != null)
            {
                request.ClientAssertion = assertion;
                request.ClientCredentialStyle = ClientCredentialStyle.PostBody;
            }
        }

        _logger.LogDebug("refresh token request to: {endpoint}", request.Address);
        var response = await oidc.HttpClient.RequestRefreshTokenAsync(request, cancellationToken);

        var token = new UserToken();
        if (response.IsError)
        {
            token.Error = response.Error;
        }
        else
        {
            token.AccessToken = response.AccessToken;
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
        UserTokenRequestParameters parameters,
        CancellationToken cancellationToken = default)
    {
        _logger.LogTrace("Revoking refresh token: {token}", refreshToken);
        
        var oidc = await _configurationService.GetOpenIdConnectConfigurationAsync(parameters.ChallengeScheme);

        if (string.IsNullOrEmpty(oidc.RevocationEndpoint))
        {
            throw new InvalidOperationException("Revocation endpoint not configured");
        }

        var request = new TokenRevocationRequest
        {
            Address = oidc.RevocationEndpoint,
            
            ClientId = oidc.ClientId,
            ClientSecret = oidc.ClientSecret,
            ClientCredentialStyle = _options.ClientCredentialStyle,
            
            Token = refreshToken,
            TokenTypeHint = OidcConstants.TokenTypes.RefreshToken
        };
        
        request.Options.TryAdd(ClientCredentialsTokenManagementDefaults.TokenRequestParametersOptionsName, parameters);
       
        if (parameters.Assertion != null)
        {
            request.ClientAssertion = parameters.Assertion;
            request.ClientCredentialStyle = ClientCredentialStyle.PostBody;
        }
        else
        {
            var assertion = await _clientAssertionService.GetClientAssertionAsync(OpenIdConnectTokenManagementDefaults.ClientCredentialsClientNamePrefix + oidc.Scheme, parameters);
            if (assertion != null)
            {
                request.ClientAssertion = parameters.Assertion;
                request.ClientCredentialStyle = ClientCredentialStyle.PostBody;
            }
        }
        
        _logger.LogDebug("token revocation request to: {endpoint}", request.Address);
        var response = await oidc.HttpClient.RevokeTokenAsync(request, cancellationToken);

        if (response.IsError)
        {
            _logger.LogInformation("Error revoking refresh token. Error = {error}", response.Error);
        }
    }
}