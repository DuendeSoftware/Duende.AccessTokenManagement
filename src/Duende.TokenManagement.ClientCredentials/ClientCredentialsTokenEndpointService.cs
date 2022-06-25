// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel.Client;
using Microsoft.Extensions.Logging;

namespace Duende.TokenManagement.ClientCredentials;

/// <summary>
/// Implements token endpoint operations using IdentityModel
/// </summary>
public class ClientCredentialsTokenEndpointService : IClientCredentialsTokenEndpointService
{
    private readonly IClientCredentialsConfigurationService _configService;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<ClientCredentialsTokenEndpointService> _logger;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="configService"></param>
    /// <param name="httpClientFactory"></param>
    /// <param name="logger"></param>
    public ClientCredentialsTokenEndpointService(
        IClientCredentialsConfigurationService configService,
        IHttpClientFactory httpClientFactory,
        ILogger<ClientCredentialsTokenEndpointService> logger)
    {
        _configService = configService;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<TokenResponse> RequestToken(
        string? clientName = TokenManagementDefaults.DefaultTokenClientName,
        AccessTokenParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        if (clientName == null) throw new ArgumentNullException(nameof(clientName));
        if (clientName == null) throw new ArgumentNullException(nameof(clientName));
        _logger.LogDebug("Requesting client access token for client: {client}", clientName);

        parameters ??= new AccessTokenParameters();

        var requestDetails = await _configService.GetClientCredentialsRequestAsync(clientName, parameters);


        requestDetails.Options.TryAdd(TokenManagementDefaults.AccessTokenParametersOptionsName, parameters);


        if (!string.IsNullOrWhiteSpace(parameters.Resource))
        {
            requestDetails.Resource.Add(parameters.Resource);
        }

        var httpClient = _httpClientFactory.CreateClient(TokenManagementDefaults.BackChannelHttpClientName);
        return await httpClient.RequestClientCredentialsTokenAsync(requestDetails, cancellationToken);
    }

}