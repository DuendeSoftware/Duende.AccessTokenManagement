// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading;
using System.Threading.Tasks;

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <summary>
/// Abstraction for token endpoint operations
/// </summary>
public interface IUserTokenEndpointService
{
    /// <summary>
    /// Refreshes a user access token.
    /// </summary>
    /// <param name="refreshToken"></param>
    /// <param name="parameters"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<UserToken> RefreshAccessTokenAsync(
        string refreshToken,
        UserTokenRequestParameters parameters,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a refresh token.
    /// </summary>
    /// <param name="parameters"></param>
    /// <param name="cancellationToken"></param>
    /// <param name="refreshToken"></param>
    /// <returns></returns>
    Task RevokeRefreshTokenAsync(
        string refreshToken,
        UserTokenRequestParameters parameters,
        CancellationToken cancellationToken = default);
}