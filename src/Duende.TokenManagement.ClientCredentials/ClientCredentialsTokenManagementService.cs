// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.Extensions.Logging;

namespace Duende.TokenManagement.ClientCredentials
{
    /// <summary>
    /// Implements basic token management logic
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
        /// <param name="distributedAccessTokenCachenCache"></param>
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
        public async Task<string?> GetAccessTokenAsync(
            string clientName = TokenManagementDefaults.DefaultTokenClientName, 
            ClientAccessTokenParameters? parameters = null,
            CancellationToken cancellationToken = default)
        {
            parameters ??= new ClientAccessTokenParameters();
            
            if (parameters.ForceRenewal == false)
            {
                var item = await _distributedAccessTokenCache.GetAsync(clientName, parameters, cancellationToken);
                if (item != null)
                {
                    return item.AccessToken;
                }
            }

            try
            {
                return await _sync.Dictionary.GetOrAdd(clientName, _ =>
                {
                    return new Lazy<Task<string?>>(async () =>
                    {
                        var response = await _clientCredentialsTokenEndpointService.RequestToken(clientName, parameters, cancellationToken);

                        if (response.IsError)
                        {
                            _logger.LogError("Error requesting access token for client {clientName}. Error = {error}. Error description = {errorDescription}", clientName, response.Error, response.ErrorDescription);
                            return null;
                        }

                        await _distributedAccessTokenCache.SetAsync(clientName, response.AccessToken, response.ExpiresIn, parameters, cancellationToken);
                        return response.AccessToken;
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
            ClientAccessTokenParameters? parameters = null, 
            CancellationToken cancellationToken = default)
        {
            parameters ??= new();
            
            return _distributedAccessTokenCache.DeleteAsync(clientName, parameters, cancellationToken);
        }
    }
}