// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading;
using System.Threading.Tasks;
using IdentityModel.Client;

namespace Duende.TokenManagement.OpenIdConnect;

/// <summary>
/// Abstraction for token endpoint operations
/// </summary>
public interface IUserTokenEndpointService
{
    /// <summary>
    /// Refreshes a user access token.
    /// </summary>
    /// <param name="request"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<UserAccessToken> RefreshAccessTokenAsync(
        string refreshToken,
        UserAccessTokenRequestParameters parameters,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a refresh token.
    /// </summary>
    /// <param name="request"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task RevokeRefreshTokenAsync(
        string refreshToken,
        UserAccessTokenRequestParameters parameters,
        CancellationToken cancellationToken = default);
}