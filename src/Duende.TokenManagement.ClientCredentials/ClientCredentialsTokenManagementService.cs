// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Duende.TokenManagement.ClientCredentials;

/// <summary>
/// Implements token management logic
/// </summary>
public class ClientCredentialsTokenManagementService : IClientCredentialsTokenManagementService
{
    private readonly ITokenRequestSynchronization _sync;
    private readonly IClientCredentialsTokenEndpointService _clientCredentialsTokenEndpointService;
    private readonly IAccessTokenCache _distributedAccessTokenCache;
    private readonly ILogger<ClientCredentialsTokenManagementService> _logger;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="sync"></param>
    /// <param name="clientCredentialsTokenEndpointService"></param>
    /// <param name="distributedAccessTokenCache"></param>
    /// <param name="logger"></param>
    public ClientCredentialsTokenManagementService(
        ITokenRequestSynchronization sync,
        IClientCredentialsTokenEndpointService clientCredentialsTokenEndpointService,
        IAccessTokenCache distributedAccessTokenCache,
        ILogger<ClientCredentialsTokenManagementService> logger)
    {
        _sync = sync;
        _clientCredentialsTokenEndpointService = clientCredentialsTokenEndpointService;
        _distributedAccessTokenCache = distributedAccessTokenCache;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<AccessToken> GetAccessTokenAsync(
        string clientName = TokenManagementDefaults.DefaultTokenClientName, 
        AccessTokenParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        parameters ??= new AccessTokenParameters();
            
        if (parameters.ForceRenewal == false)
        {
            var item = await _distributedAccessTokenCache.GetAsync(clientName, parameters, cancellationToken);
            if (item != null)
            {
                return item;
            }
        }

        try
        {
            return await _sync.Dictionary.GetOrAdd(clientName, _ =>
            {
                return new Lazy<Task<AccessToken>>(async () =>
                {
                    var response = await _clientCredentialsTokenEndpointService.RequestToken(clientName, parameters, cancellationToken);

                    if (response.IsError)
                    {
                        _logger.LogError("Error requesting access token for client {clientName}. Error = {error}. Error description = {errorDescription}", clientName, response.Error, response.ErrorDescription);
                        return new AccessToken();
                    }

                    var token = new AccessToken
                    {
                        Value = response.AccessToken,
                        Expiration = response.ExpiresIn == 0
                            ? null
                            : DateTimeOffset.UtcNow.AddSeconds(response.ExpiresIn),
                        Scope = response.Scope,
                        Resource = response.TryGet("resource")
                    };
                    
                    await _distributedAccessTokenCache.SetAsync(clientName, token, parameters, cancellationToken);
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
        AccessTokenParameters? parameters = null, 
        CancellationToken cancellationToken = default)
    {
        parameters ??= new AccessTokenParameters();
            
        return _distributedAccessTokenCache.DeleteAsync(clientName, parameters, cancellationToken);
    }
}