// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using IdentityModel.Client;
using Microsoft.Extensions.Logging;

namespace Duende.TokenManagement.ClientCredentials;

/// <summary>
/// Implements token endpoint operations using IdentityModel
/// </summary>
public class TokenEndpointService : ITokenEndpointService
{
    private readonly IClientCredentialsConfigurationService _configService;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<TokenEndpointService> _logger;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="configService"></param>
    /// <param name="httpClientFactory"></param>
    /// <param name="logger"></param>
    public TokenEndpointService(
        IClientCredentialsConfigurationService configService,
        IHttpClientFactory httpClientFactory,
        ILogger<TokenEndpointService> logger)
    {
        _configService = configService;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<TokenResponse> RequestToken(
        ClientCredentialsTokenRequest request,
        AccessTokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        parameters ??= new AccessTokenRequestParameters();
        request.Options.TryAdd(TokenManagementDefaults.AccessTokenParametersOptionsName, parameters);
        
        if (!string.IsNullOrWhiteSpace(parameters.Scope))
        {
            request.Scope = parameters.Scope;
        }
        
        if (!string.IsNullOrWhiteSpace(parameters.Resource))
        {
            request.Resource.Clear();
            request.Resource.Add(parameters.Resource);
        }

        if (parameters.Assertion != null)
        {
            request.ClientAssertion = parameters.Assertion;
        }

        var httpClient = _httpClientFactory.CreateClient(TokenManagementDefaults.BackChannelHttpClientName);
        
        _logger.LogDebug("Requesting client credentials access token at endpoint: {endpoint}", request.Address);
        return await httpClient.RequestClientCredentialsTokenAsync(request, cancellationToken);
    }
}