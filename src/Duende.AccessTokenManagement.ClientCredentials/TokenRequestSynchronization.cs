// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace Duende.AccessTokenManagement.ClientCredentials;

/// <summary>
/// Default implementation for token request synchronization primitive
/// </summary>
internal class TokenRequestSynchronization : ITokenRequestSynchronization
{
    // this is what provides the synchronization; assumes this service is a singleton in DI.
    ConcurrentDictionary<string, Lazy<Task<ClientCredentialsAccessToken>>> _dictionary { get; } = new();

    /// <inheritdoc/>
    public async Task<ClientCredentialsAccessToken> SynchronizeAsync(string name, Func<Task<ClientCredentialsAccessToken>> func)
    {
        try
        {
            return await _dictionary.GetOrAdd(name, _ =>
            {
                return new Lazy<Task<ClientCredentialsAccessToken>>(func);
            }).Value;
        }
        finally
        {
            _dictionary.TryRemove(name, out _);
        }
    }
}