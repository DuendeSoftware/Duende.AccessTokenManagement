using System.Net.Http.Json;
using System.Text.Json;
using Duende.AccessTokenManagement.OpenIdConnect;
using Microsoft.IdentityModel.Logging;
using RichardSzalay.MockHttp;

namespace Duende.AccessTokenManagement.Tests;

public class UserTokenManagementTestsShort : IntegrationTestBase
{
    public UserTokenManagementTestsShort() : base("web")
    { }
    
    
    [Fact]
    public async Task Short_token_lifetime_should_trigger_refresh()
    {
        var mockHttp = new MockHttpMessageHandler();
        AppHost.MockHttpHandler = mockHttp;
        
        // short token lifetime should trigger refresh on 1st use
        var initialTokenResponse = new
        {
            id_token = IdentityServerHost.CreateIdToken("1", "web"),
            access_token = "initial_access_token",
            expires_in = 10,
            refresh_token = "initial_refresh_token",
        };
        
        // response for re-deeming code
        mockHttp.When("/connect/token")
            .WithFormData("grant_type", "authorization_code")
            .Respond("application/json", JsonSerializer.Serialize(initialTokenResponse));
        
        // short token lifetime should trigger refresh on 1st use
        var refreshTokenResponse = new
        {
            access_token = "refreshed1_access_token",
            expires_in = 10,
            refresh_token = "refreshed1_refresh_token",
        };
        
        // response for refresh 1
        mockHttp.When("/connect/token")
            .WithFormData("grant_type", "refresh_token")
            .WithFormData("refresh_token", "initial_refresh_token")
            .Respond("application/json", JsonSerializer.Serialize(refreshTokenResponse));
        
        // short token lifetime should trigger refresh on 2st use
        var refreshTokenResponse2 = new
        {
            access_token = "refreshed2_access_token",
            expires_in = 3600,
            refresh_token = "refreshed2_refresh_token",
        };
        
        // response for refresh 1
        mockHttp.When("/connect/token")
            .WithFormData("grant_type", "refresh_token")
            .WithFormData("refresh_token", "refreshed1_refresh_token")
            .Respond("application/json", JsonSerializer.Serialize(refreshTokenResponse2));
        
        
        // setup host
        await AppHost.InitializeAsync();
        await AppHost.LoginAsync("alice");
        
        // first request should trigger refresh
        var response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token"));
        var token = await response.Content.ReadFromJsonAsync<UserToken>();

        token.IsError.ShouldBeFalse();
        token.AccessToken.ShouldBe("refreshed1_access_token");
        token.RefreshToken.ShouldBe("refreshed1_refresh_token");
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);
        
        // second request should trigger refresh
        response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token"));
        token = await response.Content.ReadFromJsonAsync<UserToken>();

        token.IsError.ShouldBeFalse();
        token.AccessToken.ShouldBe("refreshed2_access_token");
        token.RefreshToken.ShouldBe("refreshed2_refresh_token");
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);
        
        // third request should not trigger refresh
        response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token"));
        token = await response.Content.ReadFromJsonAsync<UserToken>();

        token.IsError.ShouldBeFalse();
        token.AccessToken.ShouldBe("refreshed2_access_token");
        token.RefreshToken.ShouldBe("refreshed2_refresh_token");
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);
    }
    
}