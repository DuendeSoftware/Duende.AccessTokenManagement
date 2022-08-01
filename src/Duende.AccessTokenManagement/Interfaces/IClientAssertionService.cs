// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading.Tasks;
using IdentityModel.Client;

namespace Duende.AccessTokenManagement;

/// <summary>
/// Service to create client assertions for back-channel clients
/// </summary>
public interface IClientAssertionService
{
    /// <summary>
    /// Creates a client assertion based on client or configuration scheme (if present)
    /// </summary>
    /// <param name="clientName"></param>
    /// <param name="parameters"></param>
    /// <returns></returns>
    Task<ClientAssertion?> GetClientAssertionAsync(string? clientName = null, TokenRequestParameters? parameters = null);
}