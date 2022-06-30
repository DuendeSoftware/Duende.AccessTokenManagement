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
public class ClientCredentialsTokenEndpointService : IClientCredentialsTokenEndpointService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<ClientCredentialsTokenEndpointService> _logger;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="httpClientFactory"></param>
    /// <param name="logger"></param>
    public ClientCredentialsTokenEndpointService(
        IHttpClientFactory httpClientFactory,
        ILogger<ClientCredentialsTokenEndpointService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<TokenResponse> RequestToken(
        ClientCredentialsTokenRequest request,
        ClientCredentialsTokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        parameters ??= new ClientCredentialsTokenRequestParameters();
        request.Options.TryAdd(TokenManagementDefaults.AccessTokenParametersOptionsName, parameters);
        
        var httpClient = _httpClientFactory.CreateClient(TokenManagementDefaults.BackChannelHttpClientName);
        
        _logger.LogDebug("Requesting client credentials access token at endpoint: {endpoint}", request.Address);
        return await httpClient.RequestClientCredentialsTokenAsync(request, cancellationToken);
    }
}