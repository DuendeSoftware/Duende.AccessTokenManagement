// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.Extensions.Logging;
using System.Threading;
using System.Threading.Tasks;

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <summary>
/// Delegating handler that injects the current access token into an outgoing request
/// </summary>
public class OpenIdConnectUserAccessTokenHandler : AccessTokenHandler
{
    private readonly IUserAccessor _userAccessor;
    private readonly IUserTokenManagementService _userTokenManagement;
    private readonly UserTokenRequestParameters _parameters;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="dPoPProofService"></param>
    /// <param name="dPoPNonceStore"></param>
    /// <param name="userAccessor"></param>
    /// <param name="userTokenManagement"></param>
    /// <param name="logger"></param>
    /// <param name="parameters"></param>
    public OpenIdConnectUserAccessTokenHandler(
        IDPoPProofService dPoPProofService,
        IDPoPNonceStore dPoPNonceStore,
        IUserAccessor userAccessor,
        IUserTokenManagementService userTokenManagement,
        ILogger<OpenIdConnectClientAccessTokenHandler> logger,
        UserTokenRequestParameters? parameters = null)
        : base(dPoPProofService, dPoPNonceStore, logger)
    {
        _userAccessor = userAccessor;
        _userTokenManagement = userTokenManagement;
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

        var user = await _userAccessor.GetCurrentUserAsync();

        return await _userTokenManagement.GetAccessTokenAsync(user, parameters, cancellationToken).ConfigureAwait(false);
    }
}
