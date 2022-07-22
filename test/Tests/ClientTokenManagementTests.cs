using System.Text.Json;
using ClientCredentialTests.Services;
using Duende.AccessTokenManagement;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.Extensions.DependencyInjection;
using RichardSzalay.MockHttp;

namespace ClientCredentialTests;

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

        async Task action()
        {
            var token = await sut.GetAccessTokenAsync("unknown");
        }

        await Should.ThrowAsync<InvalidOperationException>(action);
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
                client.Address = "https://as/connect/token";
                client.ClientId = "client_id";
                client.ClientSecret = "client_secret";
                client.ClientCredentialStyle = style;

                client.Scope = "scope";
                client.Resource = "resource";
            });

        var expectedRequestFormData = new Dictionary<string, string>
        {
            { "scope", "scope" },
            { "resource", "resource" },
        };

        if (style == ClientCredentialStyle.PostBody)
        {
            expectedRequestFormData.Add("client_id", "client_id");
            expectedRequestFormData.Add("client_secret", "client_secret");
        }

        var response = new
        {
            access_token = "access_token",
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

        services.AddHttpClient(AccessTokenManagementDefaults.BackChannelHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => mockHttp);

        var provider = services.BuildServiceProvider();
        var sut = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

        var token = await sut.GetAccessTokenAsync("test");
        mockHttp.VerifyNoOutstandingExpectation();

        token.Value.ShouldBe("access_token");
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
                client.Address = "https://as/connect/token";
                client.ClientId = "client_id";
            });

        var expectedResponse = new
        {
            access_token = "access_token",
            scope = "scope"
        };

        var mockHttp = new MockHttpMessageHandler();
        mockHttp.Fallback.Throw(new InvalidOperationException("No matching mock handler"));

        mockHttp.Expect("/connect/token")
            .Respond("application/json", JsonSerializer.Serialize(expectedResponse));

        services.AddHttpClient(AccessTokenManagementDefaults.BackChannelHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => mockHttp);

        var provider = services.BuildServiceProvider();
        var sut = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

        var token = await sut.GetAccessTokenAsync("test");
        mockHttp.VerifyNoOutstandingExpectation();

        token.Value.ShouldBe("access_token");
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
                client.Address = "https://as/connect/token";
                client.ClientId = "client_id";
                client.ClientSecret = "client_secret";

                client.Scope = "scope";
                client.Resource = "resource";
            });

        var request = new ClientCredentialsTokenRequestParameters
        {
            Scope = "scope_per_request",
            Resource = "resource_per_request"
        };

        var expectedRequestFormData = new Dictionary<string, string>
        {
            { "scope", "scope_per_request" },
            { "resource", "resource_per_request" },
        };

        var response = new
        {
            access_token = "access_token",
            expires_in = 60,
            scope = "scope_per_request"
        };

        var mockHttp = new MockHttpMessageHandler();
        mockHttp.Fallback.Throw(new InvalidOperationException("No matching mock handler"));

        mockHttp.Expect("/connect/token")
            .WithFormData(expectedRequestFormData)
            .Respond("application/json", JsonSerializer.Serialize(response));

        services.AddHttpClient(AccessTokenManagementDefaults.BackChannelHttpClientName)
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
                client.Address = "https://as/connect/token";
                client.ClientId = "client_id";
                client.ClientSecret = "client_secret";

                client.Scope = "scope";
                client.Resource = "resource";
            });

        var request = new ClientCredentialsTokenRequestParameters
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
            expires_in = 60,
            scope = "scope"
        };

        var mockHttp = new MockHttpMessageHandler();
        mockHttp.Fallback.Throw(new InvalidOperationException("No matching mock handler"));

        mockHttp.Expect("/connect/token")
            .WithFormData(expectedRequestFormData)
            .Respond("application/json", JsonSerializer.Serialize(expectedResponse));

        services.AddHttpClient(AccessTokenManagementDefaults.BackChannelHttpClientName)
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
                client.Address = "https://as/connect/token";
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
            expires_in = 60,
            scope = "scope"
        };

        var mockHttp = new MockHttpMessageHandler();
        mockHttp.Fallback.Throw(new InvalidOperationException("No matching mock handler"));

        mockHttp.Expect("/connect/token")
            .WithFormData(expectedRequestFormData)
            .Respond("application/json", JsonSerializer.Serialize(expectedResponse));

        services.AddHttpClient(AccessTokenManagementDefaults.BackChannelHttpClientName)
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
                client.Address = "https://as/connect/token";
                client.ClientId = "client_id";
                client.ClientSecret = "client_secret";

                client.Scope = "scope";
                client.Resource = "resource";
            });

        services.AddTransient<IClientAssertionService>(sp =>
            new TestClientAssertionService("test", "service_type", "service_value"));

        var request = new ClientCredentialsTokenRequestParameters
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
            expires_in = 60,
            scope = "scope"
        };

        var mockHttp = new MockHttpMessageHandler();
        mockHttp.Fallback.Throw(new InvalidOperationException("No matching mock handler"));

        mockHttp.Expect("/connect/token")
            .WithFormData(expectedRequestFormData)
            .Respond("application/json", JsonSerializer.Serialize(expectedResponse));

        services.AddHttpClient(AccessTokenManagementDefaults.BackChannelHttpClientName)
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
                client.Address = "https://as/connect/token";
                client.ClientId = "client_id";
            });

        var response = new
        {
            access_token = "access_token",
            expires_in = 3600,
            scope = "scope"
        };

        var mockHttp = new MockHttpMessageHandler();
        mockHttp.Fallback.Throw(new InvalidOperationException("No matching mock handler"));
        
        var mockedRequest = mockHttp.Expect("/connect/token")
            .Respond("application/json", JsonSerializer.Serialize(response));
        
        services.AddHttpClient(AccessTokenManagementDefaults.BackChannelHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => mockHttp);

        var provider = services.BuildServiceProvider();
        var sut = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

        var token = await sut.GetAccessTokenAsync("test");
        mockHttp.VerifyNoOutstandingExpectation();

        token.Value.ShouldBe("access_token");
        
        // 2nd request
        token = await sut.GetAccessTokenAsync("test");
        
        token.IsError.ShouldBeFalse();
        token.Value.ShouldBe("access_token");
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
                client.Address = "https://as/connect/token";
                client.ClientId = "client_id";
            });

        var response = new
        {
            access_token = "access_token",
            expires_in = 3600,
            scope = "scope"
        };

        var mockHttp = new MockHttpMessageHandler();
        mockHttp.Fallback.Throw(new InvalidOperationException("No matching mock handler"));
        
        mockHttp.Expect("/connect/token")
            .Respond("application/json", JsonSerializer.Serialize(response));
        
        services.AddHttpClient(AccessTokenManagementDefaults.BackChannelHttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => mockHttp);

        var provider = services.BuildServiceProvider();
        var sut = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

        var token = await sut.GetAccessTokenAsync("test");
        mockHttp.VerifyNoOutstandingExpectation();

        token.Value.ShouldBe("access_token");
        
        // 2nd request
        mockHttp.Expect("/connect/token")
            .Respond("application/json", JsonSerializer.Serialize(response));
        
        token = await sut.GetAccessTokenAsync("test", new ClientCredentialsTokenRequestParameters { ForceRenewal = true });
        
        token.IsError.ShouldBeFalse();
        token.Value.ShouldBe("access_token");
    }
}