using System.Net;
using System.Text.Json;
using Duende.AccessTokenManagement;
using IdentityModel.Client;
using Microsoft.Extensions.DependencyInjection;
using RichardSzalay.MockHttp;

namespace ClientCredentialTests;

public class ManagementServiceTests
{
    [Fact]
    public async Task Unknown_client_should_throw_exception()
    {
        var services = new ServiceCollection();

        services.AddDistributedMemoryCache();
        services.AddClientCredentialsTokenManagement();
          
        var provider = services.BuildServiceProvider();
        var sut = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

        Func<Task> action = async () =>
        {
            var token = await sut.GetAccessTokenAsync("unknown");
        };
        
        await Should.ThrowAsync<InvalidOperationException>(() => action());
        
        
        
    }
    
    [Theory]
    [InlineData(ClientCredentialStyle.AuthorizationHeader)]
    [InlineData(ClientCredentialStyle.PostBody)]
    public async Task Valid_token_request_should_return_expected_values(ClientCredentialStyle style)
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

        token.Value.ShouldBe("access_token");
        token.Scope.ShouldBe("scope");
        token.IsError.ShouldBeFalse();
        
        token.Expiration.ShouldBeGreaterThan(DateTimeOffset.Now);
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);
    }
}