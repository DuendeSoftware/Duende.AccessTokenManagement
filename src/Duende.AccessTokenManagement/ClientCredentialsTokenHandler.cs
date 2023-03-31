// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.Extensions.Logging;
using System.Threading;
using System.Threading.Tasks;

namespace Duende.AccessTokenManagement;

/// <summary>
/// Delegating handler that injects a client credentials access token into an outgoing request
/// </summary>
public class ClientCredentialsTokenHandler : AccessTokenHandler
{
    private readonly IClientCredentialsTokenManagementService _accessTokenManagementService;
    private readonly string _tokenClientName;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="dPoPProofService"></param>
    /// <param name="dPoPNonceStore"></param>
    /// <param name="accessTokenManagementService">The Access Token Management Service</param>
    /// <param name="logger"></param>
    /// <param name="tokenClientName">The name of the token client configuration</param>
    public ClientCredentialsTokenHandler(
        IDPoPProofService dPoPProofService,
        IDPoPNonceStore dPoPNonceStore,
        IClientCredentialsTokenManagementService accessTokenManagementService,
        ILogger<ClientCredentialsTokenHandler> logger,
        string tokenClientName) 
        : base(dPoPProofService, dPoPNonceStore, logger)
    {
        _accessTokenManagementService = accessTokenManagementService;
        _tokenClientName = tokenClientName;
    }

    /// <inheritdoc/>
    protected override Task<ClientCredentialsToken> GetAccessTokenAsync(bool forceRenewal, CancellationToken cancellationToken)
    {
        var parameters = new TokenRequestParameters
        {
            ForceRenewal = forceRenewal
        }; 
        return _accessTokenManagementService.GetAccessTokenAsync(_tokenClientName, parameters, cancellationToken);
    }
}