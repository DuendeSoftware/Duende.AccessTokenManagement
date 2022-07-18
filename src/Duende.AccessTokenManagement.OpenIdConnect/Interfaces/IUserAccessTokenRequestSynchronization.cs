// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Threading.Tasks;

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <summary>
/// Service to provide synchronization to token endpoint requests
/// </summary>
public interface IUserAccessTokenRequestSynchronization
{
    /// <summary>
    /// Method to perform synchronization of work.
    /// </summary>
    public Task<UserAccessToken> SynchronizeAsync(string name, Func<Task<UserAccessToken>> func);
}