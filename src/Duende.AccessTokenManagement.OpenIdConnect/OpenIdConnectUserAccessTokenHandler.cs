// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <summary>
/// Delegating handler that injects the current access token into an outgoing request
/// </summary>
public class OpenIdConnectUserAccessTokenHandler : AccessTokenHandler
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly UserTokenRequestParameters _parameters;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="dPoPProofService"></param>
    /// <param name="dPoPNonceStore"></param>
    /// <param name="httpContextAccessor"></param>
    /// <param name="options"></param>
    /// <param name="logger"></param>
    /// <param name="parameters"></param>
    public OpenIdConnectUserAccessTokenHandler(
        IDPoPProofService dPoPProofService,
        IDPoPNonceStore dPoPNonceStore,
        IHttpContextAccessor httpContextAccessor,
        IOptions<ClientCredentialsTokenManagementOptions> options,
        ILogger<OpenIdConnectClientAccessTokenHandler> logger,
        UserTokenRequestParameters? parameters = null)
        : base(dPoPProofService, dPoPNonceStore, options, logger)
    {
        _httpContextAccessor = httpContextAccessor;
        _parameters = parameters ?? new UserTokenRequestParameters();
    }

    /// <inheritdoc/>
    protected override async Task<ClientCredentialsToken> GetAccessTokenAsync(bool forceRenewal, CancellationToken cancellationToken)
    {
        var parameters = new UserTokenRequestParameters
        {
            SignInScheme = _parameters.SignInScheme,
            ChallengeScheme = _parameters.ChallengeScheme,
            Resource = _parameters.Resource,
            Context = _parameters.Context,
            ForceRenewal = forceRenewal,
        };

        return await _httpContextAccessor.HttpContext!.GetUserAccessTokenAsync(parameters).ConfigureAwait(false);
    }
}
