// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using IdentityModel.Client;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Duende.TokenManagement.ClientCredentials;

/// <summary>
/// Implements token endpoint operations using IdentityModel
/// </summary>
public class ClientCredentialsTokenEndpointService : IClientCredentialsTokenEndpointService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IOptionsSnapshot<ClientCredentialsClient> _options;
    private readonly IClientAssertionService _clientAssertionService;
    private readonly ILogger<ClientCredentialsTokenEndpointService> _logger;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="httpClientFactory"></param>
    /// <param name="clientAssertionService"></param>
    /// <param name="logger"></param>
    /// <param name="options"></param>
    public ClientCredentialsTokenEndpointService(
        IHttpClientFactory httpClientFactory,
        IOptionsSnapshot<ClientCredentialsClient> options,
        IClientAssertionService clientAssertionService,
        ILogger<ClientCredentialsTokenEndpointService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options;
        _clientAssertionService = clientAssertionService;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<ClientCredentialsAccessToken> RequestToken(
        string clientName,
        ClientCredentialsTokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        var client = _options.Get(clientName);
        
        var request = new ClientCredentialsTokenRequest
        {
            Address = client.Address,
            ClientId = client.ClientId,
            ClientSecret = client.ClientSecret,
            ClientCredentialStyle = client.ClientCredentialStyle
        };
        
        parameters ??= new ClientCredentialsTokenRequestParameters();
        
        if (!string.IsNullOrWhiteSpace(parameters.Scope))
        {
            request.Scope = parameters.Scope;
        }
        
        if (!string.IsNullOrWhiteSpace(parameters.Resource))
        {
            request.Resource.Clear();
            request.Resource.Add(parameters.Resource);
        }

        // if assertion gets passed in explicitly, use it.
        // otherwise call assertion service
        if (parameters.Assertion != null)
        {
            request.ClientAssertion = parameters.Assertion;
            request.ClientCredentialStyle = ClientCredentialStyle.PostBody;
        }
        else
        {
            var assertion = await _clientAssertionService.GetClientAssertionAsync(clientName);
                
            if (assertion != null)
            {
                request.ClientAssertion = assertion;
                request.ClientCredentialStyle = ClientCredentialStyle.PostBody;
            }
        }
        
        request.Options.TryAdd(TokenManagementDefaults.AccessTokenParametersOptionsName, parameters);

        HttpClient httpClient;
        if (client.HttpClient != null)
        {
            httpClient = client.HttpClient;
        }
        else if (!string.IsNullOrWhiteSpace(client.HttpClientName))
        {
            httpClient = _httpClientFactory.CreateClient(client.HttpClientName);    
        }
        else
        {
            httpClient = _httpClientFactory.CreateClient(TokenManagementDefaults.BackChannelHttpClientName);    
        }
        
        _logger.LogDebug("Requesting client credentials access token at endpoint: {endpoint}", request.Address);
        var response = await httpClient.RequestClientCredentialsTokenAsync(request, cancellationToken);

        if (response.IsError)
        {
            return new ClientCredentialsAccessToken
            {
                Error = response.Error
            };
        }
        
        return new ClientCredentialsAccessToken
        {
            Value = response.AccessToken,
            Expiration = response.ExpiresIn == 0
                ? DateTimeOffset.MaxValue
                : DateTimeOffset.UtcNow.AddSeconds(response.ExpiresIn),
            Scope = response.Scope
        };
    }
}