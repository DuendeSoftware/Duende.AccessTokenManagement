// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading;
using System.Threading.Tasks;

namespace Duende.AccessTokenManagement;

/// <summary>
/// Abstraction for token endpoint operations
/// </summary>
public interface IClientCredentialsTokenEndpointService
{
    /// <summary>
    /// Requests a client credentials access token.
    /// </summary>
    /// <param name="clientName"></param>
    /// <param name="parameters"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<ClientCredentialsToken> RequestToken(
        string clientName,
        TokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default);
}