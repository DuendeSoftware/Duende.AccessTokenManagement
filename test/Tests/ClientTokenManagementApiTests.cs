// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Duende.IdentityServer.Configuration;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Text.Json;

namespace Duende.AccessTokenManagement.Tests;

public class ClientTokenManagementApiTests : IntegrationTestBase
{
    private static readonly string _jwkJson;

    private HttpClient _client;
    private IClientCredentialsTokenManagementService _tokenService;
    private IHttpClientFactory _clientFactory;
    private ClientCredentialsClient _clientOptions;

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
        _clientOptions = provider.GetRequiredService<IOptionsMonitor<ClientCredentialsClient>>().Get("test");
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
    public async Task api_returning_401_should_send_new_access_token()
    {
        var count = 0;
        string? accessToken = null;

        ApiHost.ApiInvoked += ctx =>
        {
            var at = ctx.Request.Headers.Authorization.FirstOrDefault()?.Split(' ', StringSplitOptions.RemoveEmptyEntries)?[1].Trim();
            if (accessToken == null)
            {
                ApiHost.ApiStatusCodeToReturn = 401;
                accessToken = at;
            }
            else
            {
                accessToken.ShouldNotBe(at);
            }
            count++;
        };
        var client = _clientFactory.CreateClient("test");
        var apiResult = await client.GetAsync(ApiHost.Url("/test"));

        count.ShouldBe(2);
    }

    [Fact]
    public async Task dpop_clients_GetAccessTokenAsync_should_obtain_token_with_cnf()
    {
        var token = await _tokenService.GetAccessTokenAsync("test");

        token.IsError.ShouldBeFalse();
        token.DPoPJsonWebKey.ShouldNotBeNull();
        token.AccessTokenType.ShouldBe("DPoP");
        var payload = Base64UrlEncoder.Decode(token.AccessToken!.Split('.')[1]);
        var values = JsonSerializer.Deserialize<Dictionary<string, object>>(payload);
        values!.ShouldContainKey("cnf");
    }

    [Theory]
    [InlineData("RS256")]
    [InlineData("RS384")]
    [InlineData("RS512")]
    [InlineData("PS256")]
    [InlineData("PS384")]
    [InlineData("PS512")]
    public async Task using_different_rsa_keys_for_dpop_should_obtain_token_with_cnf(string alg)
    {
        var key = CryptoHelper.CreateRsaSecurityKey();
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
        jwk.Alg = alg;
        var jwkJson = JsonSerializer.Serialize(jwk);
        
        _clientOptions.DPoPJsonWebKey = jwkJson;

        var token = await _tokenService.GetAccessTokenAsync("test");

        token.IsError.ShouldBeFalse();
        token.DPoPJsonWebKey.ShouldNotBeNull();
        token.AccessTokenType.ShouldBe("DPoP");
        var payload = Base64UrlEncoder.Decode(token.AccessToken!.Split('.')[1]);
        var values = JsonSerializer.Deserialize<Dictionary<string, object>>(payload);
        values!.ShouldContainKey("cnf");

        var json = JsonSerializer.Deserialize<JsonElement>(values!["cnf"].ToString()!);
        var jkt = json.GetString("jkt");
        jkt.ShouldBe(Base64Url.Encode(jwk.ComputeJwkThumbprint()));
    }

    [Theory]
    [InlineData("ES256")]
    [InlineData("ES384")]
    [InlineData("ES512")]
    public async Task using_different_ec_keys_for_dpop_should_obtain_token_with_cnf(string alg)
    {
        var key = CryptoHelper.CreateECDsaSecurityKey();
        var jwk = JsonWebKeyConverter.ConvertFromECDsaSecurityKey(key);
        jwk.Alg = alg;
        var jwkJson = JsonSerializer.Serialize(jwk);

        _clientOptions.DPoPJsonWebKey = jwkJson;

        var token = await _tokenService.GetAccessTokenAsync("test");

        token.IsError.ShouldBeFalse();
        token.DPoPJsonWebKey.ShouldNotBeNull();
        token.AccessTokenType.ShouldBe("DPoP");
        var payload = Base64UrlEncoder.Decode(token.AccessToken!.Split('.')[1]);
        var values = JsonSerializer.Deserialize<Dictionary<string, object>>(payload);
        values!.ShouldContainKey("cnf");

        var json = JsonSerializer.Deserialize<JsonElement>(values!["cnf"].ToString()!);
        var jkt = json.GetString("jkt");
        jkt.ShouldBe(Base64Url.Encode(jwk.ComputeJwkThumbprint()));
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
    public async Task when_api_issues_nonce_api_request_should_be_retried_with_new_nonce()
    {
        string? proofToken = null;

        var count = 0;
        string? accessToken = null;

        ApiHost.ApiInvoked += ctx =>
        {
            var at = ctx.Request.Headers.Authorization.FirstOrDefault()?.Split(' ', StringSplitOptions.RemoveEmptyEntries)?[1].Trim();
            if (count == 0)
            {
                ApiHost.ApiStatusCodeToReturn = 401;
                ctx.Response.Headers["WWW-Authenticate"] = "DPoP error=\"use_dpop_nonce\"";
                ctx.Response.Headers["DPoP-Nonce"] = "some-nonce";
                accessToken = at;
            }
            else
            {
                accessToken.ShouldBe(at);
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