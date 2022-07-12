// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Threading;
using System.Threading.Tasks;
using IdentityModel.Client;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Duende.TokenManagement.ClientCredentials;

/// <summary>
/// Implements token management logic
/// </summary>
public class ClientCredentialsTokenManagementService : IClientCredentialsTokenManagementService
{
    private readonly ITokenRequestSynchronization _sync;
    private readonly IClientCredentialsTokenEndpointService _clientCredentialsTokenEndpointService;
    private readonly IClientCredentialsTokenCache _tokenCache;
    private readonly IClientCredentialsConfigurationService _configurationService;
    private readonly ILogger<ClientCredentialsTokenManagementService> _logger;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="sync"></param>
    /// <param name="clientCredentialsTokenEndpointService"></param>
    /// <param name="tokenCache"></param>
    /// <param name="options"></param>
    /// <param name="logger"></param>
    public ClientCredentialsTokenManagementService(
        ITokenRequestSynchronization sync,
        IClientCredentialsTokenEndpointService clientCredentialsTokenEndpointService,
        IClientCredentialsTokenCache tokenCache,
        ILogger<ClientCredentialsTokenManagementService> logger)
    {
        _sync = sync;
        _clientCredentialsTokenEndpointService = clientCredentialsTokenEndpointService;
        _tokenCache = tokenCache;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<ClientCredentialsAccessToken> GetAccessTokenAsync(
        string clientName,
        ClientCredentialsTokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        parameters ??= new ClientCredentialsTokenRequestParameters();

        if (parameters.ForceRenewal == false)
        {
            var item = await _tokenCache.GetAsync(clientName, parameters, cancellationToken);
            if (item != null)
            {
                return item;
            }
        }

        try
        {
            return await _sync.Dictionary.GetOrAdd(clientName, _ =>
            {
                return new Lazy<Task<ClientCredentialsAccessToken>>(async () =>
                {
                    //request ??= await _configurationService.GetClientCredentialsRequestAsync(clientName, parameters);
                    
                    var response = await _clientCredentialsTokenEndpointService.RequestToken(clientName, parameters, cancellationToken);
                    if (response.IsError)
                    {
                        _logger.LogError(
                            "Error requesting access token for client {clientName}. Error = {error}. Error description = {errorDescription}",
                            clientName, response.Error, response.ErrorDescription);
                        
                        return new ClientCredentialsAccessToken();
                    }

                    var token = new ClientCredentialsAccessToken
                    {
                        Value = response.AccessToken,
                        Expiration = response.ExpiresIn == 0
                            ? DateTimeOffset.MaxValue
                            : DateTimeOffset.UtcNow.AddSeconds(response.ExpiresIn),
                        Scope = response.Scope,
                    };

                    await _tokenCache.SetAsync(clientName, token, parameters, cancellationToken);
                    return token;
                });
            }).Value;
        }
        finally
        {
            _sync.Dictionary.TryRemove(clientName, out _);
        }
    }


    /// <inheritdoc/>
    public Task DeleteAccessTokenAsync(
        string clientName = TokenManagementDefaults.DefaultTokenClientName,
        ClientCredentialsTokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        parameters ??= new ClientCredentialsTokenRequestParameters();

        return _tokenCache.DeleteAsync(clientName, parameters, cancellationToken);
    }
}