// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Linq;
using System.Threading.Tasks;
using IdentityModel.Client;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Duende.TokenManagement.ClientCredentials;

/// <summary>
/// Options-based configuration service for token clients
/// </summary>
public class DefaultClientCredentialsConfigurationService : IClientCredentialsConfigurationService
{
    private readonly ClientCredentialsTokenManagementOptions _clientAccessTokenManagementOptions;
    private readonly ILogger<DefaultClientCredentialsConfigurationService> _logger;
        
    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="clientAccessTokenManagementOptions"></param>
    /// <param name="logger"></param>
    public DefaultClientCredentialsConfigurationService(
        IOptions<ClientCredentialsTokenManagementOptions> clientAccessTokenManagementOptions,
        ILogger<DefaultClientCredentialsConfigurationService> logger)
    {
        _clientAccessTokenManagementOptions = clientAccessTokenManagementOptions.Value;
        _logger = logger;
    }

    /// <inheritdoc />
    public virtual async Task<ClientCredentialsTokenRequest> GetClientCredentialsRequestAsync(
        string clientName,
        AccessTokenParameters parameters)
    {
        ClientCredentialsTokenRequest? requestDetails = null;

        // if a named client configuration was passed in, try to load it
        if (string.Equals(clientName, TokenManagementDefaults.DefaultTokenClientName))
        {
            // if only one client configuration exists, load that
            if (_clientAccessTokenManagementOptions.Clients.Count == 1)
            {
                _logger.LogDebug("Reading token client configuration from single configuration entry.");
                requestDetails = _clientAccessTokenManagementOptions.Clients.First().Value;
            }
            else
            {
                throw new InvalidOperationException("More than one client configured. Specify the client name.");
            }
        }
        else
        {
            if (!_clientAccessTokenManagementOptions.Clients.TryGetValue(clientName, out requestDetails!))
            {
                throw new InvalidOperationException(
                    $"No access token client configuration found for client: {clientName}");
            }

            _logger.LogDebug("Returning token client configuration for client: {client}", clientName);
        }

        var assertion = await CreateAssertionAsync(clientName);
        if (assertion != null)
        {
            requestDetails.ClientAssertion = assertion;
        }
            
        return requestDetails;
    }

    /// <summary>
    /// Allows injecting a client assertion into outgoing requests
    /// </summary>
    /// <param name="clientName">Name of client (if present)</param>
    /// <returns></returns>
    protected virtual Task<ClientAssertion?> CreateAssertionAsync(string? clientName = null)
    {
        return Task.FromResult<ClientAssertion?>(null);
    }
}