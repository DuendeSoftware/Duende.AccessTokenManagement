// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading;
using System.Threading.Tasks;

namespace Duende.AccessTokenManagement.ClientCredentials;

/// <summary>
/// Abstraction for caching client credentials access tokens
/// </summary>
public interface IClientCredentialsTokenCache
{
    /// <summary>
    /// Caches a client access token
    /// </summary>
    /// <param name="clientName"></param>
    /// <param name="clientCredentialsAccessToken"></param>
    /// <param name="requestParameters"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task SetAsync(
        string clientName,
        ClientCredentialsAccessToken clientCredentialsAccessToken,
        ClientCredentialsTokenRequestParameters requestParameters,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves a client access token from the cache
    /// </summary>
    /// <param name="clientName"></param>
    /// <param name="requestParameters"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<ClientCredentialsAccessToken?> GetAsync(
        string clientName,
        ClientCredentialsTokenRequestParameters requestParameters,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a client access token from the cache
    /// </summary>
    /// <param name="clientName"></param>
    /// <param name="requestParameters"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task DeleteAsync(
        string clientName,
        ClientCredentialsTokenRequestParameters requestParameters,
        CancellationToken cancellationToken = default);
}