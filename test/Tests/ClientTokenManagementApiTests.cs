
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
    private IHttpClientFactory _clientFactory;

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
        services.AddClientCredentialsHttpClient("test", "test")
            .AddHttpMessageHandler(() =>
            {
                return new ApiHandler(ApiHost.Server.CreateHandler());
            });

        var provider = services.BuildServiceProvider();
        _client = provider.GetRequiredService<IHttpClientFactory>().CreateClient("test");
        _tokenService = provider.GetRequiredService<IClientCredentialsTokenManagementService>();
        _clientFactory = provider.GetRequiredService<IHttpClientFactory>();
    }
    public class ApiHandler : DelegatingHandler
    {
        private HttpMessageHandler? _innerHandler;

        public ApiHandler(HttpMessageHandler innerHandler) 
        {
            _innerHandler = innerHandler;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (_innerHandler != null)
            {
                InnerHandler = _innerHandler;
                _innerHandler = null;
            }
            return base.SendAsync(request, cancellationToken);
        }
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
    
    [Fact]
    public async Task dpop_tokens_should_be_passed_to_api()
    {
        string? scheme = null;
        string? proofToken = null;

        ApiHost.ApiInvoked += ctx => 
        {
            scheme = ctx.Request.Headers.Authorization.FirstOrDefault()?.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0];
            proofToken = ctx.Request.Headers["DPoP"].FirstOrDefault()?.ToString();
        };
        var client = _clientFactory.CreateClient("test");
        var apiResult = await client.GetAsync(ApiHost.Url("/test"));

        scheme.ShouldBe("DPoP");
        proofToken.ShouldNotBeNull();
    }

    [Fact]
    public async Task api_issued_nonce_should_retry_with_new_nonce()
    {
        string? proofToken = null;

        var count = 0;

        ApiHost.ApiInvoked += ctx =>
        {
            if (count == 0)
            {
                ApiHost.ApiStatusCodeToReturn = 401;
                ctx.Response.Headers["DPoP-Nonce"] = "some-nonce";
            }
            proofToken = ctx.Request.Headers["DPoP"].FirstOrDefault()?.ToString();
            count++;
        };
        var client = _clientFactory.CreateClient("test");
        var apiResult = await client.GetAsync(ApiHost.Url("/test"));

        count.ShouldBe(2);
        var payload = Base64UrlEncoder.Decode(proofToken!.Split('.')[1]);
        var values = JsonSerializer.Deserialize<Dictionary<string, object>>(payload);
        values!["nonce"].ToString().ShouldBe("some-nonce");
    }
}