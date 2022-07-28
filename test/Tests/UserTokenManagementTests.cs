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
    public async Task Logged_on_user_should_return_access_and_refresh_token()
    {
        await AppHost.LoginAsync("alice");

        var response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token"));
        var token = await response.Content.ReadFromJsonAsync<UserToken>();

        token.AccessToken.ShouldNotBeNull();
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);
        token.RefreshToken.ShouldNotBeNull();
        token.IsError.ShouldBeFalse();
    }
}