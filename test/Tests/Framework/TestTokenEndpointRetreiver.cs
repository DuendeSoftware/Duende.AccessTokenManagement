// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

namespace Duende.AccessTokenManagement.Tests;

public class TestTokenEndpointRetriever(string tokenEndpoint = "https://identityserver/connect/token") : ITokenEndpointRetriever
{
    public Task<string> GetAsync(ClientCredentialsClient client)
    {
        return Task.FromResult(tokenEndpoint);
    }
}