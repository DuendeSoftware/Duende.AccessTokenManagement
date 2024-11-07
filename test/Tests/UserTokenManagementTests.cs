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
        // This test makes an initial token request using code flow and then
        // refreshes the token a couple of times.
        
        // We mock the expiration of the first few token responses to be short
        // enough that we will automatically refresh immediately when attempting
        // to use the tokens, while the final response gets a long refresh time,
        // allowing us to verify that the token is not refreshed. 

        var mockHttp = new MockHttpMessageHandler();
        AppHost.IdentityServerHttpHandler = mockHttp;

        // Respond to code flow with a short token lifetime so that we trigger refresh on 1st use
        var initialTokenResponse = new
        {
            id_token = IdentityServerHost.CreateIdToken("1", "web"),
            access_token = "initial_access_token",
            token_type = "token_type",
            expires_in = 10,
            refresh_token = "initial_refresh_token",
        };
        mockHttp.When("/connect/token")
            .WithFormData("grant_type", "authorization_code")
            .Respond("application/json", JsonSerializer.Serialize(initialTokenResponse));

        // Respond to refresh with a short token lifetime so that we trigger another refresh on 2nd use
        var refreshTokenResponse = new
        {
            access_token = "refreshed1_access_token",
            token_type = "token_type1",
            expires_in = 10,
            refresh_token = "refreshed1_refresh_token",
        };
        mockHttp.When("/connect/token")
            .WithFormData("grant_type", "refresh_token")
            .WithFormData("refresh_token", "initial_refresh_token")
            .Respond("application/json", JsonSerializer.Serialize(refreshTokenResponse));

        // Respond to second refresh with a long token lifetime so that we don't trigger another refresh on 3rd use
        var refreshTokenResponse2 = new
        {
            access_token = "refreshed2_access_token",
            token_type = "token_type2",
            expires_in = 3600,
            refresh_token = "refreshed2_refresh_token",
        };
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

    [Fact]
    public async Task Resources_get_distinct_tokens()
    {
        var mockHttp = new MockHttpMessageHandler();
        AppHost.IdentityServerHttpHandler = mockHttp;

        // no resource specified
        var initialTokenResponse = new
        {
            id_token = IdentityServerHost.CreateIdToken("1", "web"),
            access_token = "access_token_without_resource",
            token_type = "token_type",
            expires_in = 3600,
            refresh_token = "initial_refresh_token",
        };
        mockHttp.When("/connect/token")
            .WithFormData("grant_type", "authorization_code")
            .Respond("application/json", JsonSerializer.Serialize(initialTokenResponse));

        // resource 1 specified 
        var resource1TokenResponse = new
        {
            access_token = "urn:api1_access_token",
            token_type = "token_type1",
            expires_in = 3600,
            refresh_token = "initial_refresh_token",
        };
        mockHttp.When("/connect/token")
            .WithFormData("grant_type", "refresh_token")
            .WithFormData("resource", "urn:api1")
            .Respond("application/json", JsonSerializer.Serialize(resource1TokenResponse));

        // resource 2 specified 
        var resource2TokenResponse = new
        {
            access_token = "urn:api2_access_token",
            token_type = "token_type1",
            expires_in = 3600,
            refresh_token = "initial_refresh_token",
        };
        mockHttp.When("/connect/token")
            .WithFormData("grant_type", "refresh_token")
            .WithFormData("resource", "urn:api2")
            .Respond("application/json", JsonSerializer.Serialize(resource2TokenResponse));

        // setup host
        await AppHost.InitializeAsync();
        await AppHost.LoginAsync("alice");

        // first request - no resource
        var response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token"));
        var token = await response.Content.ReadFromJsonAsync<UserToken>();

        token.ShouldNotBeNull();
        token.IsError.ShouldBeFalse();
        token.AccessToken.ShouldBe("access_token_without_resource");
        token.RefreshToken.ShouldBe("initial_refresh_token");
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);

        // second request - with resource api1
        response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token_with_resource/urn:api1"));
        token = await response.Content.ReadFromJsonAsync<UserToken>();

        token.ShouldNotBeNull();
        token.IsError.ShouldBeFalse();
        token.AccessToken.ShouldBe("urn:api1_access_token");
        token.RefreshToken.ShouldBe("initial_refresh_token"); // This doesn't change with resources!
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);

        // third request - with resource api2
        response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token_with_resource/urn:api2"));
        token = await response.Content.ReadFromJsonAsync<UserToken>();

        token.ShouldNotBeNull();
        token.IsError.ShouldBeFalse();
        token.AccessToken.ShouldBe("urn:api2_access_token");
        token.RefreshToken.ShouldBe("initial_refresh_token");
        token.Expiration.ShouldNotBe(DateTimeOffset.MaxValue);
    }

    [Fact]
    public async Task Refresh_responses_without_refresh_token_use_old_refresh_token()
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

        // note lack of refresh_token
        var refreshTokenResponse = new
        {
            access_token = "refreshed1_access_token",
            token_type = "token_type1",
            expires_in = 3600,
        };

        // response for refresh
        mockHttp.When("/connect/token")
            .WithFormData("grant_type", "refresh_token")
            .WithFormData("refresh_token", "initial_refresh_token")
            .Respond("application/json", JsonSerializer.Serialize(refreshTokenResponse));

        // setup host
        await AppHost.InitializeAsync();
        await AppHost.LoginAsync("alice");

        // first request should trigger refresh
        var response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token"));
        var token = await response.Content.ReadFromJsonAsync<UserToken>();

        token.ShouldNotBeNull();
        token.IsError.ShouldBeFalse();
        token.RefreshToken.ShouldBe("initial_refresh_token");
    }

    [Fact]
    public async Task Multiple_users_have_distinct_tokens_across_refreshes()
    {
        // setup host
        AppHost.ClientId = "web.short";
        await AppHost.InitializeAsync();
        await AppHost.LoginAsync("alice");

        var firstResponse = await AppHost.BrowserClient.GetAsync(AppHost.Url("/call_api"));
        var firstToken = await firstResponse.Content.ReadFromJsonAsync<TokenEchoResponse>();
        var secondResponse = await AppHost.BrowserClient.GetAsync(AppHost.Url("/call_api"));
        var secondToken = await secondResponse.Content.ReadFromJsonAsync<TokenEchoResponse>();
        firstToken.ShouldNotBeNull();
        secondToken.ShouldNotBeNull();
        secondToken.sub.ShouldBe(firstToken.sub);
        secondToken.token.ShouldNotBe(firstToken.token);

        await AppHost.LoginAsync("bob");
        var thirdResponse = await AppHost.BrowserClient.GetAsync(AppHost.Url("/call_api"));
        var thirdToken = await thirdResponse.Content.ReadFromJsonAsync<TokenEchoResponse>();
        thirdToken.ShouldNotBeNull(); 
        thirdToken.sub.ShouldNotBe(secondToken.sub);
        thirdToken.token.ShouldNotBe(firstToken.token);
    }
}