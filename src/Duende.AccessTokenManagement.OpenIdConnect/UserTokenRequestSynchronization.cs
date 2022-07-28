// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <summary>
/// Default implementation for token request synchronization primitive
/// </summary>
internal class UserTokenRequestSynchronization : IUserTokenRequestSynchronization
{
    // this is what provides the synchronization; assumes this service is a singleton in DI.
    ConcurrentDictionary<string, Lazy<Task<UserToken>>> _dictionary { get; } = new();

    /// <inheritdoc/>
    public async Task<UserToken> SynchronizeAsync(string name, Func<Task<UserToken>> func)
    {
        try
        {
            return await _dictionary.GetOrAdd(name, _ =>
            {
                return new Lazy<Task<UserToken>>(func);
            }).Value;
        }
        finally
        {
            _dictionary.TryRemove(name, out _);
        }
    }
}