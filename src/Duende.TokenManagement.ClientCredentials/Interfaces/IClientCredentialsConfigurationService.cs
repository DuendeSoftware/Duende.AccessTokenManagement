// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading.Tasks;
using IdentityModel.Client;

namespace Duende.TokenManagement.ClientCredentials;

/// <summary>
/// Retrieves request details for client credentials, refresh and revocation requests
/// </summary>
public interface IClientCredentialsConfigurationService
{
    /// <summary>
    /// Returns the request details for a client credentials token request
    /// </summary>
    /// <param name="clientName"></param>
    /// <param name="parameters"></param>
    /// <returns></returns>
    Task<ClientCredentialsTokenRequest> GetClientCredentialsRequestAsync(string clientName, AccessTokenRequestParameters? parameters);
}