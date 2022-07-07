// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Duende.TokenManagement.ClientCredentials;

namespace Duende.TokenManagement.OpenIdConnect;

/// <summary>
/// Abstraction for managing user access tokens
/// </summary>
public interface IUserTokenManagementService
{
    /// <summary>
    /// Returns the user access token. If the current token is expired, it will try to refresh it.
    /// </summary>
    /// <param name="user"></param>
    /// <param name="parameters"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<UserAccessToken> GetAccessTokenAsync(
        ClaimsPrincipal user, 
        UserAccessTokenRequestParameters? parameters = null, 
        CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Revokes the current refresh token
    /// </summary>
    /// <param name="user"></param>
    /// <param name="parameters"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task RevokeRefreshTokenAsync(
        ClaimsPrincipal user, 
        UserAccessTokenRequestParameters? parameters = null, 
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Requests a token using client credentials
    /// </summary>
    /// <param name="parameters"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<ClientCredentialsAccessToken> GetClientCredentialAccessTokenAsync(
        ClientCredentialsTokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default);
}