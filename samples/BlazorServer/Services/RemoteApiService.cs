// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text.Json;

namespace BlazorServer.Services;

public class RemoteApiService
{
    private readonly HttpClient _client;

    public RemoteApiService(
        IHttpClientFactory factory)
    {
        _client = factory.CreateClient("demoApiClient");
    }

    private record Claim(string type, object value);

    public async Task<string> GetData()
    {
        var response = await _client.GetStringAsync("test");
        var json = JsonSerializer.Deserialize<IEnumerable<Claim>>(response);
        return JsonSerializer.Serialize(json, new JsonSerializerOptions { WriteIndented = true });
    }
}