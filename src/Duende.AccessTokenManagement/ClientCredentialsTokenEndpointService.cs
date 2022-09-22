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

namespace Duende.AccessTokenManagement;

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
    public async Task<ClientCredentialsToken> RequestToken(
        string clientName,
        TokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        var client = _options.Get(clientName);

        if (string.IsNullOrWhiteSpace(client.TokenEndpoint) || string.IsNullOrEmpty(client.ClientId))
        {
            throw new InvalidOperationException("unknown client");
        }
        
        var request = new ClientCredentialsTokenRequest
        {
            Address = client.TokenEndpoint,
            Scope = client.Scope,
            ClientId = client.ClientId,
            ClientSecret = client.ClientSecret,
            ClientCredentialStyle = client.ClientCredentialStyle
        };
        request.Parameters.AddRange(client.Parameters);
        
        parameters ??= new TokenRequestParameters();
        
        if (!string.IsNullOrWhiteSpace(parameters.Scope))
        {
            request.Scope = parameters.Scope;
        }
        
        if (!string.IsNullOrWhiteSpace(parameters.Resource))
        {
            request.Resource.Clear();
            request.Resource.Add(parameters.Resource);
        }
        else if (!string.IsNullOrWhiteSpace(client.Resource))
        {
            request.Resource.Clear();
            request.Resource.Add(client.Resource);
        }

        request.Parameters.AddRange(parameters.Parameters);

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
        
        request.Options.TryAdd(ClientCredentialsTokenManagementDefaults.TokenRequestParametersOptionsName, parameters);

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
            httpClient = _httpClientFactory.CreateClient(ClientCredentialsTokenManagementDefaults.BackChannelHttpClientName);    
        }
        
        _logger.LogDebug("Requesting client credentials access token at endpoint: {endpoint}", request.Address);
        var response = await httpClient.RequestClientCredentialsTokenAsync(request, cancellationToken);

        if (response.IsError)
        {
            return new ClientCredentialsToken
            {
                Error = response.Error
            };
        }
        
        return new ClientCredentialsToken
        {
            AccessToken = response.AccessToken,
            Expiration = response.ExpiresIn == 0
                ? DateTimeOffset.MaxValue
                : DateTimeOffset.UtcNow.AddSeconds(response.ExpiresIn),
            Scope = response.Scope
        };
    }
}