using System.Net.Http.Json;
using System.Text.Json;
using Duende.AccessTokenManagement.OpenIdConnect;
using RichardSzalay.MockHttp;

namespace Duende.AccessTokenManagement.Tests;

public class UserTokenManagementTests : IntegrationTestBase
{
    public UserTokenManagementTests() : base("web")
    { }
    
    [Fact]
    public async Task Anonymous_user_should_return_user_token_error()
    {
        var response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token"));
        var token = await response.Content.ReadFromJsonAsync<UserToken>();

        token.IsError.ShouldBeTrue();
    }
    
    [Fact]
    public async Task Anonymous_user_should_return_client_token()
    {
        var response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/client_token"));
        var token = await response.Content.ReadFromJsonAsync<ClientCredentialsToken>();

        token.AccessToken.ShouldNotBeNull();
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);
        
        token.IsError.ShouldBeFalse();
    }

    [Fact]
    public async Task Standard_initial_token_response_should_return_expected_values()
    {
        var mockHttp = new MockHttpMessageHandler();
        AppHost.MockHttpHandler = mockHttp;
        
        var initialTokenResponse = new
        {
            id_token = IdentityServerHost.CreateIdToken("1", "web"),
            access_token = "initial_access_token",
            expires_in = 3600,
            refresh_token = "initial_refresh_token",
        };
        
        // response for re-deeming code
        mockHttp.When("/connect/token")
            .WithFormData("grant_type", "authorization_code")
            .Respond("application/json", JsonSerializer.Serialize(initialTokenResponse));
        
        await AppHost.InitializeAsync();
        await AppHost.LoginAsync("alice");

        var response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token"));
        var token = await response.Content.ReadFromJsonAsync<UserToken>();

        token.IsError.ShouldBeFalse();
        token.AccessToken.ShouldBe("initial_access_token");
        token.RefreshToken.ShouldBe("initial_refresh_token");
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);
    }
    
    [Fact]
    public async Task Missing_expires_in_should_result_in_long_lived_token()
    {
        var mockHttp = new MockHttpMessageHandler();
        AppHost.MockHttpHandler = mockHttp;
        
        var initialTokenResponse = new
        {
            id_token = IdentityServerHost.CreateIdToken("1", "web"),
            access_token = "initial_access_token",
            refresh_token = "initial_refresh_token",
        };
        
        // response for re-deeming code
        mockHttp.When("/connect/token")
            .WithFormData("grant_type", "authorization_code")
            .Respond("application/json", JsonSerializer.Serialize(initialTokenResponse));
        
        await AppHost.InitializeAsync();
        await AppHost.LoginAsync("alice");

        var response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token"));
        var token = await response.Content.ReadFromJsonAsync<UserToken>();

        token.IsError.ShouldBeFalse();
        token.AccessToken.ShouldBe("initial_access_token");
        token.RefreshToken.ShouldBe("initial_refresh_token");
        token.Expiration.ShouldBe(DateTimeOffset.MaxValue);
    }
    
    [Fact]
    public async Task Missing_initial_refresh_token_response_should_return_access_token()
    {
        var mockHttp = new MockHttpMessageHandler();
        AppHost.MockHttpHandler = mockHttp;
        
        var initialTokenResponse = new
        {
            id_token = IdentityServerHost.CreateIdToken("1", "web"),
            access_token = "initial_access_token",
            expires_in = 3600
        };
        
        // response for re-deeming code
        mockHttp.When("/connect/token")
            .WithFormData("grant_type", "authorization_code")
            .Respond("application/json", JsonSerializer.Serialize(initialTokenResponse));
        
        await AppHost.InitializeAsync();
        await AppHost.LoginAsync("alice");

        var response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token"));
        var token = await response.Content.ReadFromJsonAsync<UserToken>();

        token.IsError.ShouldBeFalse();
        token.AccessToken.ShouldBe("initial_access_token");
        token.RefreshToken.ShouldBeNull();
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);
    }
}