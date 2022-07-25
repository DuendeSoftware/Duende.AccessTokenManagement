using System.Net.Http.Json;
using System.Text.Json;
using Duende.AccessTokenManagement.OpenIdConnect;
using RichardSzalay.MockHttp;

namespace Duende.AccessTokenManagement.Tests;

public class UserTokenManagementTestsShort : IntegrationTestBase
{
    public UserTokenManagementTestsShort() : base("web.short")
    { }
    
    [Fact]
    public async Task Missing_expires_in_should_result_in_long_lived_token()
    {
        var mockHttp = new MockHttpMessageHandler();
        AppHost.MockHttpHandler = mockHttp;
        
        var tokenResponse = new
        {
            access_token = "access_token",
            refresh_token = "refresh_token",
        };
        
        mockHttp.When("/connect/token")
            .WithFormData("grant_type", "refresh_token")
            .Respond("application/json", JsonSerializer.Serialize(tokenResponse));
        
        await AppHost.InitializeAsync();
        await AppHost.LoginAsync("alice");

        var response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token"));
        var token = await response.Content.ReadFromJsonAsync<UserAccessToken>();

        token.AccessToken.ShouldBe("access_token");
        token.RefreshToken.ShouldBe("refresh_token");
        token.Expiration.ShouldBe(DateTimeOffset.MaxValue);
        token.IsError.ShouldBeFalse();
    }
    
    [Fact]
    public async Task Missing_refresh_token_should_not_return_refresh_token()
    {
        var mockHttp = new MockHttpMessageHandler();
        AppHost.MockHttpHandler = mockHttp;
        
        var tokenResponse = new
        {
            access_token = "access_token",
            expires_in = 10
        };
        
        mockHttp.When("/connect/token")
            .WithFormData("grant_type", "refresh_token")
            .Respond("application/json", JsonSerializer.Serialize(tokenResponse));
        
        await AppHost.InitializeAsync();
        await AppHost.LoginAsync("alice");

        var response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token"));
        var token = await response.Content.ReadFromJsonAsync<UserAccessToken>();

        token.AccessToken.ShouldBe("access_token");
        token.RefreshToken.ShouldBeNull();
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);
        token.IsError.ShouldBeFalse();
    }
}