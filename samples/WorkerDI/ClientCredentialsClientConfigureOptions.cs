using Duende.AccessTokenManagement;
using IdentityModel.Client;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace WorkerService;

public class ClientCredentialsClientConfigureOptions : IConfigureNamedOptions<ClientCredentialsClient>
{
    private readonly DiscoveryCache _cache;

    public ClientCredentialsClientConfigureOptions(DiscoveryCache cache)
    {
        _cache = cache;
    }
    
    public void Configure(ClientCredentialsClient options)
    {
        throw new System.NotImplementedException();
    }

    public void Configure(string? name, ClientCredentialsClient options)
    {
        if (name == "demo.jwt")
        {
            options.Authority = "https://demo.duendesoftware.com";
            options.ClientId = "m2m.short.jwt";
            options.Scope = "api";
        }
    }
}