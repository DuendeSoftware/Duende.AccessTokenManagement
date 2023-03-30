// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Threading;
using System.Threading.Tasks;

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <summary>
/// Delegating handler that injects the current access token into an outgoing request
/// </summary>
public class OpenIdConnectClientAccessTokenHandler : AccessTokenHandler
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly UserTokenRequestParameters _parameters;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="dPoPProofService"></param>
    /// <param name="dPoPNonceStore"></param>
    /// <param name="httpContextAccessor"></param>
    /// <param name="logger"></param>
    /// <param name="parameters"></param>
    public OpenIdConnectClientAccessTokenHandler(
        IDPoPProofService dPoPProofService,
        IDPoPNonceStore dPoPNonceStore,
        IHttpContextAccessor httpContextAccessor, 
        ILogger<OpenIdConnectClientAccessTokenHandler> logger,
        UserTokenRequestParameters? parameters = null)
        : base(dPoPProofService, dPoPNonceStore, logger)
    {
        _httpContextAccessor = httpContextAccessor;
        _parameters = parameters ?? new UserTokenRequestParameters();
    }

    /// <inheritdoc/>
    protected async override Task<ClientCredentialsToken> GetAccessTokenAsync(bool forceRenewal, CancellationToken cancellationToken)
    {
        var parameters = new UserTokenRequestParameters
        {
            ChallengeScheme = _parameters.ChallengeScheme,
            Scope = _parameters.Scope,
            Resource = _parameters.Resource,
            Parameters = _parameters.Parameters,
            Assertion = _parameters.Assertion,
            Context = _parameters.Context,
            ForceRenewal = forceRenewal,
        };

        return await _httpContextAccessor.HttpContext!.GetClientAccessTokenAsync(parameters).ConfigureAwait(false);
    }
}