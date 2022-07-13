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
    private readonly ILogger<ClientCredentialsTokenEndpointService> _logger;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="httpClientFactory"></param>
    /// <param name="logger"></param>
    /// <param name="options"></param>
    public ClientCredentialsTokenEndpointService(
        IHttpClientFactory httpClientFactory,
        IOptionsSnapshot<ClientCredentialsClient> options,
        ILogger<ClientCredentialsTokenEndpointService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _options = options;
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

        if (parameters.Assertion != null)
        {
            request.ClientAssertion = parameters.Assertion;
            request.ClientCredentialStyle = ClientCredentialStyle.PostBody;
        }
        else
        {
            var assertion = await CreateAssertionAsync(clientName, parameters);
            if (assertion != null)
            {
                request.ClientAssertion = assertion;
                request.ClientCredentialStyle = ClientCredentialStyle.PostBody;
            }
        }
        
        request.Options.TryAdd(TokenManagementDefaults.AccessTokenParametersOptionsName, parameters);

        HttpClient httpClient;
        if (!string.IsNullOrWhiteSpace(client.HttpClientName))
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
    
    /// <summary>
    /// Allows injecting a client assertion into outgoing requests
    /// </summary>
    /// <param name="clientName">Name of client (if present)</param>
    /// <param name="parameters">Per request parameters (if present)</param>
    /// <returns></returns>
    protected virtual Task<ClientAssertion?> CreateAssertionAsync(string clientName, ClientCredentialsTokenRequestParameters parameters)
    {
        return Task.FromResult<ClientAssertion?>(null);
    }
}