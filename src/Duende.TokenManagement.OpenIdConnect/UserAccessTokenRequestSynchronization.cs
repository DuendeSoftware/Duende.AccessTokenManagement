// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace Duende.TokenManagement.OpenIdConnect;

/// <summary>
/// Default implementation for token request synchronization primitive
/// </summary>
internal class UserAccessTokenRequestSynchronization : IUserAccessTokenRequestSynchronization
{
    /// <inheritdoc />
    public ConcurrentDictionary<string, Lazy<Task<UserAccessToken>>> Dictionary { get; } = new();
}