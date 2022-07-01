using System.Net.Http;
using System.Threading.Tasks;

namespace WorkerService;

public class TypedClient
{
    private readonly HttpClient _client;

    public TypedClient(HttpClient client)
    {
        _client = client;
    }

    public async Task<string> CallApi()
    {
        return await _client.GetStringAsync("test");
    }
}