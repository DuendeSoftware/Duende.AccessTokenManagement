// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using System.Net;
using System.Text.Json;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using RichardSzalay.MockHttp;

namespace Duende.AccessTokenManagement.Tests;

public class ClientTokenManagementTests
{
    [Fact]
    public async Task Unknown_client_should_throw_exception()
    {
        var services = new ServiceCollection();

        services.AddDistributedMemoryCache();
        services.AddClientCredentialsTokenManagement();

        var provider = services.BuildServiceProvider();
        var sut = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

        var action = async () => await sut.GetAccessTokenAsync("unknown");

        (await Should.ThrowAsync<InvalidOperationException>(action))
            .Message.ShouldBe("No ClientId configured for client unknown");
    }

    [Fact]
    public async Task Missing_client_id_throw_exception()
    {
        var services = new ServiceCollection();

        services.AddDistributedMemoryCache();
        services.AddClientCredentialsTokenManagement()
            .AddClient("test", client =>
            {
                client.TokenEndpoint = "https://as/connect/token";
                client.ClientId = null;
            });

        var provider = services.BuildServiceProvider();
        var sut = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

        var action = async () => await sut.GetAccessTokenAsync("test");

        (await Should.ThrowAsync<InvalidOperationException>(action))
            .Message.ShouldBe("No ClientId configured for client test");
    }


    [Fact]
    public async Task Missing_tokenEndpoint_throw_exception()
    {
        var services = new ServiceCollection();

        services.AddDistributedMemoryCache();
        services.AddClientCredentialsTokenManagement()
            .AddClient("test", client =>
            {
                client.TokenEndpoint = null;
                client.ClientId = "test";
            });

        var provider = services.BuildServiceProvider();
        var sut = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

        var action = async () => await sut.GetAccessTokenAsync("test");

        (await Should.ThrowAsync<InvalidOperationException>(action))
            .Message.ShouldBe("No TokenEndpoint configured for client test");
    }

    [Theory]
    [InlineData(ClientCredentialStyle.AuthorizationHeader)]
    [InlineData(ClientCredentialStyle.PostBody)]
    public async Task Token_request_and_response_should_have_expected_values(ClientCredentialStyle style)
    {
        var services = new ServiceCollection();

        services.AddDistributedMemoryCache();
        services.AddClientCredentialsTokenManagement()
            .AddClient("test", client =>
            {
                client.TokenEndpoint = "https://as/connect/token";
                client.ClientId = "client_id";
                client.ClientSecret = "client_secret";
                client.ClientCredentialStyle = style;

                client.Scope = "scope";
                client.Resource = "resource";
                client.Parameters.Add("audience", "audience");
            });

        var expectedRequestFormData = new Dictionary<string, string>
        {
            { "scope", "scope" },
            { "resource", "resource" },
            { "audience", "audience" },
        };

        if (style == ClientCredentialStyle.PostBody)
        {
            expectedRequestFormData.Add("client_id", "client_id");
            expectedRequestFormData.Add("client_secret", "client_secret");
        }

        var response = new
        {
            access_token = "access_token",
            token_type = "token_type",
            expires_in = 60,
            scope = "scope"
        };

        var mockHttp = new MockHttpMessageHandler();
        mockHttp.Fallback.Throw(new InvalidOperationException("No matching mock handler"));

        if (style == ClientCredentialStyle.PostBody)
        {
            mockHttp.Expect("/connect/token")
                .WithFormData(expectedRequestFormData)
                .Respond("application/json", JsonSerializer.Serialize(response));
        }
        else if (style == ClientCredentialStyle.AuthorizationHeader)
        {
            mockHttp.Expect("/connect/token")
                .WithFormData(expectedRequestFormData)
                .WithHeaders("Authorization",
                    "Basic " + BasicAuthenticationOAuthHeaderValue.EncodeCredential("client_id", "client_secret"))
                .Respond("application/json", JsonSerializer.Serialize(response));
        }

        services.AddHttpClient(ClientCredentialsTokenManagementDefaults.BackChannelHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => mockHttp);

        var provider = services.BuildServiceProvider();
        var sut = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

        var token = await sut.GetAccessTokenAsync("test");
        mockHttp.VerifyNoOutstandingExpectation();

        token.AccessToken.ShouldBe("access_token");
        token.AccessTokenType.ShouldBe("token_type");
        token.Scope.ShouldBe("scope");
        token.IsError.ShouldBeFalse();

        token.Expiration.ShouldBeGreaterThan(DateTimeOffset.Now);
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);
    }


    [Fact]
    public async Task Missing_expires_in_response_should_create_long_lived_token()
    {
        var services = new ServiceCollection();

        services.AddDistributedMemoryCache();
        services.AddClientCredentialsTokenManagement()
            .AddClient("test", client =>
            {
                client.TokenEndpoint = "https://as/connect/token";
                client.ClientId = "client_id";
            });

        var expectedResponse = new
        {
            access_token = "access_token",
            token_type = "token_type",
            scope = "scope"
        };

        var mockHttp = new MockHttpMessageHandler();
        mockHttp.Fallback.Throw(new InvalidOperationException("No matching mock handler"));

        mockHttp.Expect("/connect/token")
            .Respond("application/json", JsonSerializer.Serialize(expectedResponse));

        services.AddHttpClient(ClientCredentialsTokenManagementDefaults.BackChannelHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => mockHttp);

        var provider = services.BuildServiceProvider();
        var sut = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

        var token = await sut.GetAccessTokenAsync("test");
        mockHttp.VerifyNoOutstandingExpectation();

        token.AccessToken.ShouldBe("access_token");
        token.AccessTokenType.ShouldBe("token_type");
        token.Scope.ShouldBe("scope");
        token.IsError.ShouldBeFalse();

        token.Expiration.ShouldBe(DateTimeOffset.MaxValue);
    }

    [Fact]
    public async Task Request_parameters_should_take_precedence_over_configuration()
    {
        var services = new ServiceCollection();

        services.AddDistributedMemoryCache();
        services.AddClientCredentialsTokenManagement()
            .AddClient("test", client =>
            {
                client.TokenEndpoint = "https://as/connect/token";
                client.ClientId = "client_id";
                client.ClientSecret = "client_secret";

                client.Scope = "scope";
                client.Resource = "resource";
                client.Parameters.Add("audience", "audience");
            });

        var request = new TokenRequestParameters
        {
            Scope = "scope_per_request",
            Resource = "resource_per_request",
            Parameters =
            {
                { "audience", "audience_per_request" },
            },
        };

        var expectedRequestFormData = new Dictionary<string, string>
        {
            { "scope", "scope_per_request" },
            { "resource", "resource_per_request" },
            { "audience", "audience_per_request" },
        };

        var response = new
        {
            access_token = "access_token",
            token_type = "token_type",
            expires_in = 60,
            scope = "scope_per_request"
        };

        var mockHttp = new MockHttpMessageHandler();
        mockHttp.Fallback.Throw(new InvalidOperationException("No matching mock handler"));

        mockHttp.Expect("/connect/token")
            .WithFormData(expectedRequestFormData)
            .Respond("application/json", JsonSerializer.Serialize(response));

        services.AddHttpClient(ClientCredentialsTokenManagementDefaults.BackChannelHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => mockHttp);

        var provider = services.BuildServiceProvider();
        var sut = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

        var token = await sut.GetAccessTokenAsync("test", request);
        mockHttp.VerifyNoOutstandingExpectation();

        token.IsError.ShouldBeFalse();
    }

    [Fact]
    public async Task Request_assertions_should_be_sent_correctly()
    {
        var services = new ServiceCollection();

        services.AddDistributedMemoryCache();
        services.AddClientCredentialsTokenManagement()
            .AddClient("test", client =>
            {
                client.TokenEndpoint = "https://as/connect/token";
                client.ClientId = "client_id";
                client.ClientSecret = "client_secret";

                client.Scope = "scope";
                client.Resource = "resource";
            });

        var request = new TokenRequestParameters
        {
            Assertion = new()
            {
                Type = "type",
                Value = "value"
            }
        };

        var expectedRequestFormData = new Dictionary<string, string>
        {
            { OidcConstants.TokenRequest.ClientAssertionType, "type" },
            { OidcConstants.TokenRequest.ClientAssertion, "value" },
        };

        var expectedResponse = new
        {
            access_token = "access_token",
            token_type = "token_type",
            expires_in = 60,
            scope = "scope"
        };

        var mockHttp = new MockHttpMessageHandler();
        mockHttp.Fallback.Throw(new InvalidOperationException("No matching mock handler"));

        mockHttp.Expect("/connect/token")
            .WithFormData(expectedRequestFormData)
            .Respond("application/json", JsonSerializer.Serialize(expectedResponse));

        services.AddHttpClient(ClientCredentialsTokenManagementDefaults.BackChannelHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => mockHttp);

        var provider = services.BuildServiceProvider();
        var sut = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

        var token = await sut.GetAccessTokenAsync("test", request);
        mockHttp.VerifyNoOutstandingExpectation();

        token.IsError.ShouldBeFalse();
    }

    [Fact]
    public async Task Service_assertions_should_be_sent_correctly()
    {
        var services = new ServiceCollection();

        services.AddDistributedMemoryCache();
        services.AddClientCredentialsTokenManagement()
            .AddClient("test", client =>
            {
                client.TokenEndpoint = "https://as/connect/token";
                client.ClientId = "client_id";
                client.ClientSecret = "client_secret";

                client.Scope = "scope";
                client.Resource = "resource";
            });

        services.AddTransient<IClientAssertionService>(sp =>
            new TestClientAssertionService("test", "service_type", "service_value"));

        var expectedRequestFormData = new Dictionary<string, string>
        {
            { OidcConstants.TokenRequest.ClientAssertionType, "service_type" },
            { OidcConstants.TokenRequest.ClientAssertion, "service_value" },
        };

        var expectedResponse = new
        {
            access_token = "access_token",
            token_type = "token_type",
            expires_in = 60,
            scope = "scope"
        };

        var mockHttp = new MockHttpMessageHandler();
        mockHttp.Fallback.Throw(new InvalidOperationException("No matching mock handler"));

        mockHttp.Expect("/connect/token")
            .WithFormData(expectedRequestFormData)
            .Respond("application/json", JsonSerializer.Serialize(expectedResponse));

        services.AddHttpClient(ClientCredentialsTokenManagementDefaults.BackChannelHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => mockHttp);

        var provider = services.BuildServiceProvider();
        var sut = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

        var token = await sut.GetAccessTokenAsync("test");
        mockHttp.VerifyNoOutstandingExpectation();

        token.IsError.ShouldBeFalse();
    }

    [Fact]
    public async Task Request_assertion_should_take_precedence_over_service_assertion()
    {
        var services = new ServiceCollection();

        services.AddDistributedMemoryCache();
        services.AddClientCredentialsTokenManagement()
            .AddClient("test", client =>
            {
                client.TokenEndpoint = "https://as/connect/token";
                client.ClientId = "client_id";
                client.ClientSecret = "client_secret";

                client.Scope = "scope";
                client.Resource = "resource";
            });

        services.AddTransient<IClientAssertionService>(sp =>
            new TestClientAssertionService("test", "service_type", "service_value"));

        var request = new TokenRequestParameters
        {
            Assertion = new()
            {
                Type = "request_type",
                Value = "request_value"
            }
        };

        var expectedRequestFormData = new Dictionary<string, string>
        {
            { OidcConstants.TokenRequest.ClientAssertionType, "request_type" },
            { OidcConstants.TokenRequest.ClientAssertion, "request_value" },
        };

        var expectedResponse = new
        {
            access_token = "access_token",
            token_type = "token_type",
            expires_in = 60,
            scope = "scope"
        };

        var mockHttp = new MockHttpMessageHandler();
        mockHttp.Fallback.Throw(new InvalidOperationException("No matching mock handler"));

        mockHttp.Expect("/connect/token")
            .WithFormData(expectedRequestFormData)
            .Respond("application/json", JsonSerializer.Serialize(expectedResponse));

        services.AddHttpClient(ClientCredentialsTokenManagementDefaults.BackChannelHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => mockHttp);

        var provider = services.BuildServiceProvider();
        var sut = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

        var token = await sut.GetAccessTokenAsync("test", request);
        mockHttp.VerifyNoOutstandingExpectation();

        token.IsError.ShouldBeFalse();
    }

    [Fact]
    public async Task Service_should_hit_network_only_once_and_then_use_cache()
    {
        var services = new ServiceCollection();

        services.AddDistributedMemoryCache();
        services.AddClientCredentialsTokenManagement()
            .AddClient("test", client =>
            {
                client.TokenEndpoint = "https://as/connect/token";
                client.ClientId = "client_id";
            });

        var response = new
        {
            access_token = "access_token",
            token_type = "token_type",
            expires_in = 3600,
            scope = "scope"
        };

        var mockHttp = new MockHttpMessageHandler();
        mockHttp.Fallback.Throw(new InvalidOperationException("No matching mock handler"));

        var mockedRequest = mockHttp.Expect("/connect/token")
            .Respond("application/json", JsonSerializer.Serialize(response));

        services.AddHttpClient(ClientCredentialsTokenManagementDefaults.BackChannelHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => mockHttp);

        var provider = services.BuildServiceProvider();
        var sut = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

        var token = await sut.GetAccessTokenAsync("test");
        mockHttp.VerifyNoOutstandingExpectation();

        token.AccessToken.ShouldBe("access_token");
        token.AccessTokenType.ShouldBe("token_type");

        // 2nd request
        token = await sut.GetAccessTokenAsync("test");

        token.IsError.ShouldBeFalse();
        token.AccessToken.ShouldBe("access_token");
        token.AccessTokenType.ShouldBe("token_type");
        mockHttp.GetMatchCount(mockedRequest).ShouldBe(1);
    }
    
    [Fact]
    public async Task Service_should_hit_network_when_cache_throws_exception()
    {
        var services = new ServiceCollection();

        services.AddTransient<IDistributedCache, TestDistributedCache>();
        services.AddClientCredentialsTokenManagement()
            .AddClient("test", client =>
            {
                client.TokenEndpoint = "https://as/connect/token";
                client.ClientId = "client_id";
            });

        var response = new
        {
            access_token = "access_token",
            token_type = "token_type",
            expires_in = 3600,
            scope = "scope"
        };

        var mockHttp = new MockHttpMessageHandler();
        mockHttp.Fallback.Throw(new InvalidOperationException("No matching mock handler"));

        var mockedRequest = mockHttp.Expect("/connect/token")
            .Respond("application/json", JsonSerializer.Serialize(response));

        services.AddHttpClient(ClientCredentialsTokenManagementDefaults.BackChannelHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => mockHttp);

        var provider = services.BuildServiceProvider();
        var sut = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

        var token = await sut.GetAccessTokenAsync("test");
        token.IsError.ShouldBeFalse();
        token.AccessToken.ShouldBe("access_token");
        token.AccessTokenType.ShouldBe("token_type");
        mockHttp.GetMatchCount(mockedRequest).ShouldBe(1);
    }

    [Fact]
    public async Task Service_should_always_hit_network_with_force_renewal()
    {
        var services = new ServiceCollection();

        services.AddDistributedMemoryCache();
        services.AddClientCredentialsTokenManagement()
            .AddClient("test", client =>
            {
                client.TokenEndpoint = "https://as/connect/token";
                client.ClientId = "client_id";
            });

        var response = new
        {
            access_token = "access_token",
            token_type = "token_type",
            expires_in = 3600,
            scope = "scope"
        };

        var mockHttp = new MockHttpMessageHandler();
        mockHttp.Fallback.Throw(new InvalidOperationException("No matching mock handler"));

        mockHttp.Expect("/connect/token")
            .Respond("application/json", JsonSerializer.Serialize(response));

        services.AddHttpClient(ClientCredentialsTokenManagementDefaults.BackChannelHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => mockHttp);

        var provider = services.BuildServiceProvider();
        var sut = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

        var token = await sut.GetAccessTokenAsync("test");
        mockHttp.VerifyNoOutstandingExpectation();

        token.AccessToken.ShouldBe("access_token");
        token.AccessTokenType.ShouldBe("token_type");

        // 2nd request
        mockHttp.Expect("/connect/token")
            .Respond("application/json", JsonSerializer.Serialize(response));

        token = await sut.GetAccessTokenAsync("test", new TokenRequestParameters { ForceRenewal = true });

        token.IsError.ShouldBeFalse();
        token.AccessToken.ShouldBe("access_token");
        token.AccessTokenType.ShouldBe("token_type");
    }

    [Fact]
    public async Task client_with_dpop_key_should_send_proof_token()
    {
        var proof = new TestDPoPProofService() { ProofToken = "proof_token" };

        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services.AddSingleton<IDPoPProofService>(proof);

        services.AddClientCredentialsTokenManagement()
            .AddClient("test", client =>
            {
                client.TokenEndpoint = "https://as/connect/token";
                client.ClientId = "client_id";
                client.DPoPJsonWebKey = "key";
            });

        var expectedResponse = new
        {
            access_token = "access_token",
            token_type = "token_type",
            scope = "scope"
        };

        var mockHttp = new MockHttpMessageHandler();
        mockHttp.Fallback.Throw(new InvalidOperationException("No matching mock handler"));

        mockHttp.Expect("/connect/token")
            .With(m => m.Headers.Any(h => h.Key == "DPoP" && h.Value.FirstOrDefault() == "proof_token"))
            .Respond("application/json", JsonSerializer.Serialize(expectedResponse));

        services.AddHttpClient(ClientCredentialsTokenManagementDefaults.BackChannelHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => mockHttp);

        var provider = services.BuildServiceProvider();
        var sut = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

        var token = await sut.GetAccessTokenAsync("test");
        mockHttp.VerifyNoOutstandingExpectation();

        token.IsError.ShouldBeFalse();
        token.DPoPJsonWebKey.ShouldBe("key");
    }

    [Fact]
    public async Task client_should_use_nonce_when_sending_dpop_proof()
    {
        var proof = new TestDPoPProofService() { ProofToken = "proof_token", AppendNonce = true };

        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services.AddSingleton<IDPoPProofService>(proof);

        services.AddClientCredentialsTokenManagement()
            .AddClient("test", client =>
            {
                client.TokenEndpoint = "https://as/connect/token";
                client.ClientId = "client_id";
                client.DPoPJsonWebKey = "key";
            });

        var expectedResponse = new
        {
            access_token = "access_token",
            token_type = "token_type",
            scope = "scope"
        };

        var mockHttp = new MockHttpMessageHandler();
        mockHttp.Fallback.Throw(new InvalidOperationException("No matching mock handler"));

        mockHttp.Expect("/connect/token")
            .With(m => m.Headers.Any(h => h.Key == "DPoP" && h.Value.FirstOrDefault() == "proof_token"))
            .Respond(HttpStatusCode.BadRequest, 
                new[] { new KeyValuePair<string, string>("DPoP-Nonce", "some_nonce") }, 
                "application/json", 
                JsonSerializer.Serialize(new { error = "use_dpop_nonce" }));
        
        mockHttp.Expect("/connect/token")
            .With(m => m.Headers.Any(h => h.Key == "DPoP" && h.Value.First() == ("proof_tokensome_nonce")))
            .Respond("application/json", JsonSerializer.Serialize(expectedResponse));

        services.AddHttpClient(ClientCredentialsTokenManagementDefaults.BackChannelHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => mockHttp);

        var provider = services.BuildServiceProvider();
        var sut = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

        var token = await sut.GetAccessTokenAsync("test");
        mockHttp.VerifyNoOutstandingExpectation();

        token.IsError.ShouldBeFalse();
        token.DPoPJsonWebKey.ShouldBe("key");
    }
}