// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net.Http;
using System.Threading.Tasks;

namespace WebJarJwt;

public abstract class TypedClient
{
    private readonly HttpClient _client;

    public TypedClient(HttpClient client)
    {
        _client = client;
    }

    public virtual async Task<string> CallApi()
    {
        return await _client.GetStringAsync("test");
    }
}

public class TypedUserClient : TypedClient
{
    public TypedUserClient(HttpClient client) : base(client)
    {
    }
}

public class TypedClientClient : TypedClient
{
    public TypedClientClient(HttpClient client) : base(client)
    {
    }
}