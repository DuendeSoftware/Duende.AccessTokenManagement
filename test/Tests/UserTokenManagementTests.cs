// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

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
        var response = await AppHost.BrowserClient!.GetAsync(AppHost.Url("/user_token"));
        var token = await response.Content.ReadFromJsonAsync<UserToken>();

        token!.IsError.ShouldBeTrue();
    }
    
    [Fact]
    public async Task Anonymous_user_should_return_client_token()
    {
        AppHost.IdentityServerHttpHandler = new MockHttpMessageHandler();

        var response = await AppHost.BrowserClient!.GetAsync(AppHost.Url("/client_token"));
        var token = await response.Content.ReadFromJsonAsync<ClientCredentialsToken>();

        token!.AccessToken.ShouldNotBeNull();
        token.AccessTokenType.ShouldBe("Bearer");
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);
        
        token.IsError.ShouldBeFalse();
    }

    [Fact]
    public async Task Standard_initial_token_response_should_return_expected_values()
    {
        var mockHttp = new MockHttpMessageHandler();
        AppHost.IdentityServerHttpHandler = mockHttp;
        
        var initialTokenResponse = new
        {
            id_token = IdentityServerHost.CreateIdToken("1", "web"),
            access_token = "initial_access_token",
            token_type = "token_type",
            expires_in = 3600,
            refresh_token = "initial_refresh_token",
        };
        
        // response for re-deeming code
        mockHttp.When("/connect/token")
            .WithFormData("grant_type", "authorization_code")
            .Respond("application/json", JsonSerializer.Serialize(initialTokenResponse));
        
        await AppHost.InitializeAsync();
        await AppHost.LoginAsync("alice");

        // 1st request
        var response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token"));
        var token = await response.Content.ReadFromJsonAsync<UserToken>();

        token.ShouldNotBeNull();
        token.IsError.ShouldBeFalse();
        token.AccessToken.ShouldBe("initial_access_token");
        token.AccessTokenType.ShouldBe("token_type");
        token.RefreshToken.ShouldBe("initial_refresh_token");
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);
        
        // 2nd request should not trigger a token request
        response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token"));
        token = await response.Content.ReadFromJsonAsync<UserToken>();

        token.ShouldNotBeNull();
        token.IsError.ShouldBeFalse();
        token.AccessToken.ShouldBe("initial_access_token");
        token.AccessTokenType.ShouldBe("token_type");
        token.RefreshToken.ShouldBe("initial_refresh_token");
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);
    }
    
    [Fact]
    public async Task Missing_expires_in_should_result_in_long_lived_token()
    {
        var mockHttp = new MockHttpMessageHandler();
        AppHost.IdentityServerHttpHandler = mockHttp;
        
        var initialTokenResponse = new
        {
            id_token = IdentityServerHost.CreateIdToken("1", "web"),
            access_token = "initial_access_token",
            token_type = "token_type",
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

        token.ShouldNotBeNull();
        token.IsError.ShouldBeFalse();
        token.AccessToken.ShouldBe("initial_access_token");
        token.AccessTokenType.ShouldBe("token_type");
        token.RefreshToken.ShouldBe("initial_refresh_token");
        token.Expiration.ShouldBe(DateTimeOffset.MaxValue);
    }
    
    [Fact]
    public async Task Missing_initial_refresh_token_response_should_return_access_token()
    {
        var mockHttp = new MockHttpMessageHandler();
        AppHost.IdentityServerHttpHandler = mockHttp;
        
        var initialTokenResponse = new
        {
            id_token = IdentityServerHost.CreateIdToken("1", "web"),
            access_token = "initial_access_token",
            token_type = "token_type",
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

        token.ShouldNotBeNull();
        token.IsError.ShouldBeFalse();
        token.AccessToken.ShouldBe("initial_access_token");
        token.AccessTokenType.ShouldBe("token_type");
        token.RefreshToken.ShouldBeNull();
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);
    }
    
    [Fact]
    public async Task Missing_initial_refresh_token_and_expired_access_token_should_return_initial_access_token()
    {
        var mockHttp = new MockHttpMessageHandler();
        AppHost.IdentityServerHttpHandler = mockHttp;
        
        var initialTokenResponse = new
        {
            id_token = IdentityServerHost.CreateIdToken("1", "web"),
            access_token = "initial_access_token",
            token_type = "token_type",
            expires_in = 10
        };
        
        // response for re-deeming code
        mockHttp.When("/connect/token")
            .WithFormData("grant_type", "authorization_code")
            .Respond("application/json", JsonSerializer.Serialize(initialTokenResponse));
        
        await AppHost.InitializeAsync();
        await AppHost.LoginAsync("alice");

        var response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token"));
        var token = await response.Content.ReadFromJsonAsync<UserToken>();

        token.ShouldNotBeNull();
        token.IsError.ShouldBeFalse();
        token.AccessToken.ShouldBe("initial_access_token");
        token.AccessTokenType.ShouldBe("token_type");
        token.RefreshToken.ShouldBeNull();
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);
    }
    
    [Fact]
    public async Task Short_token_lifetime_should_trigger_refresh()
    {
        var mockHttp = new MockHttpMessageHandler();
        AppHost.IdentityServerHttpHandler = mockHttp;
        
        // short token lifetime should trigger refresh on 1st use
        var initialTokenResponse = new
        {
            id_token = IdentityServerHost.CreateIdToken("1", "web"),
            access_token = "initial_access_token",
            token_type = "token_type",
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
            token_type = "token_type1",
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
            token_type = "token_type2",
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

        token.ShouldNotBeNull();
        token.IsError.ShouldBeFalse();
        token.AccessToken.ShouldBe("refreshed1_access_token");
        token.AccessTokenType.ShouldBe("token_type1");
        token.RefreshToken.ShouldBe("refreshed1_refresh_token");
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);
        
        // second request should trigger refresh
        response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token"));
        token = await response.Content.ReadFromJsonAsync<UserToken>();

        token.ShouldNotBeNull();
        token.IsError.ShouldBeFalse();
        token.AccessToken.ShouldBe("refreshed2_access_token");
        token.AccessTokenType.ShouldBe("token_type2");
        token.RefreshToken.ShouldBe("refreshed2_refresh_token");
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);
        
        // third request should not trigger refresh
        response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token"));
        token = await response.Content.ReadFromJsonAsync<UserToken>();

        token.ShouldNotBeNull();
        token.IsError.ShouldBeFalse();
        token.AccessToken.ShouldBe("refreshed2_access_token");
        token.AccessTokenType.ShouldBe("token_type2");
        token.RefreshToken.ShouldBe("refreshed2_refresh_token");
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);
    }
}