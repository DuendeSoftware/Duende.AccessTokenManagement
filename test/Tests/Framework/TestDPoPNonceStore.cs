// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


namespace Duende.AccessTokenManagement.Tests;

public class TestDPoPNonceStore : IDPoPNonceStore
{
    public Task<string?> GetNonceAsync(DPoPNonceContext context, CancellationToken cancellationToken = default)
    {
        return Task.FromResult<string?>(null);
    }

    public Task StoreNonceAsync(DPoPNonceContext context, string nonce, CancellationToken cancellationToken = default)
    {
        return Task.CompletedTask;
    }
}