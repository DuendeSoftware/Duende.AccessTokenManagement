
using Duende.IdentityServer.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;

namespace Duende.AccessTokenManagement.Tests;

public class ClientTokenManagementApiTests : IntegrationTestBase
{
    private static readonly string _jwkJson;

    private HttpClient _client;
    private IClientCredentialsTokenManagementService _tokenService;

    static ClientTokenManagementApiTests()
    {
        var key = CryptoHelper.CreateRsaSecurityKey();
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
        jwk.Alg = "RS256";
        _jwkJson = JsonSerializer.Serialize(jwk);
    }

    public ClientTokenManagementApiTests()
    {
        var services = new ServiceCollection();

        services.AddDistributedMemoryCache();
        services.AddClientCredentialsTokenManagement()
            .AddClient("test", client =>
            {
                client.TokenEndpoint = "https://identityserver/connect/token";
                client.ClientId = "client_credentials_client";
                client.ClientSecret = "secret";
                client.Scope = "scope1";
                client.HttpClient = IdentityServerHost.HttpClient;
                client.DPoPJsonWebKey = _jwkJson;
            });
        services.AddClientCredentialsHttpClient("test", "test");

        var provider = services.BuildServiceProvider();
        _client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("test");
        _tokenService = provider.GetRequiredService<IClientCredentialsTokenManagementService>();
    }

    [Fact]
    public async Task for_dpop_clients_GetAccessTokenAsync_should_obtain_token_with_cnf()
    {
        var token = await _tokenService.GetAccessTokenAsync("test");
        
        token.IsError.ShouldBeFalse();
        token.DPoPJsonWebKey.ShouldNotBeNull();
        token.AccessTokenType.ShouldBe("DPoP");
        var payload = Base64UrlEncoder.Decode(token.AccessToken!.Split('.')[1]);
        var values = JsonSerializer.Deserialize<Dictionary<string, object>>(payload);
        values!.ShouldContainKey("cnf");
    }
}