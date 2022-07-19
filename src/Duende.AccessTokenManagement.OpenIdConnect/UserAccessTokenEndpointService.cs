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
public class UserAccessTokenEndpointService : IUserTokenEndpointService
{
    private readonly IOpenIdConnectConfigurationService _configurationService;
    private readonly IClientAssertionService _clientAssertionService;
    private readonly ILogger<UserAccessTokenEndpointService> _logger;
    private readonly UserAccessTokenManagementOptions _options;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="options"></param>
    /// <param name="clientAssertionService"></param>
    /// <param name="logger"></param>
    /// <param name="configurationService"></param>
    public UserAccessTokenEndpointService(
        IOpenIdConnectConfigurationService configurationService,
        IOptions<UserAccessTokenManagementOptions> options,
        IClientAssertionService clientAssertionService,
        ILogger<UserAccessTokenEndpointService> logger)
    {
        _configurationService = configurationService;
        _clientAssertionService = clientAssertionService;
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
        
        request.Options.TryAdd(AccessTokenManagementDefaults.AccessTokenParametersOptionsName, parameters);
        
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

        var response = await oidc.HttpClient.RequestRefreshTokenAsync(request, cancellationToken);

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
        
        request.Options.TryAdd(AccessTokenManagementDefaults.AccessTokenParametersOptionsName, parameters);
       
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
        
        var response = await oidc.HttpClient.RevokeTokenAsync(request, cancellationToken);

        if (response.IsError)
        {
            _logger.LogInformation("Error revoking refresh token. Error = {error}", response.Error);
        }
    }
    
    private async Task ApplyAssertionAsync(ProtocolRequest request, string schemename, ClientCredentialsTokenRequestParameters parameters)
    {
        if (parameters.Assertion != null)
        {
            request.ClientAssertion = parameters.Assertion;
            request.ClientCredentialStyle = ClientCredentialStyle.PostBody;
        }
        else
        {
            var assertion = await _clientAssertionService.GetClientAssertionAsync(OpenIdConnectTokenManagementDefaults.ClientCredentialsClientNamePrefix + schemename, parameters);
            if (assertion != null)
            {
                request.ClientAssertion = parameters.Assertion;
                request.ClientCredentialStyle = ClientCredentialStyle.PostBody;
            }
        }
    }
}