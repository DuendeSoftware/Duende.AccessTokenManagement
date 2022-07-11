using System.Text.Json;

namespace BlazorServer.Services;

public class RemoteApiService
{
    private readonly ApiClient _client;
    //private readonly IHttpClientFactory _httpClientFactory;

    public RemoteApiService(ApiClient client)
    {
        _client = client;
        //_httpClientFactory = httpClientFactory;
    }

    private record Claim(string type, object value);
    
    public async Task<string> GetData()
    {
        // var client = _httpClientFactory.CreateClient("client");
        // var data = await client.GetStringAsync("test");

        var data = await _client.CallRemoteApi();

        var json = JsonSerializer.Deserialize<IEnumerable<Claim>>(data);
        return JsonSerializer.Serialize(json, new JsonSerializerOptions { WriteIndented = true });
    }
}