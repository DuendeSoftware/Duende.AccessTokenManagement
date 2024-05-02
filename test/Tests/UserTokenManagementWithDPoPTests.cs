// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Duende.AccessTokenManagement.OpenIdConnect;
using IdentityModel;
using Microsoft.IdentityModel.Tokens;
using RichardSzalay.MockHttp;

namespace Duende.AccessTokenManagement.Tests;

public class UserTokenManagementWithDPoPTests : IntegrationTestBase
{
    // (An example jwk from RFC7517)
    const string _privateJWK = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\"e\":\"AQAB\",\"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q\",\"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\",\"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk\",\"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\",\"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk\",\"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";

    public UserTokenManagementWithDPoPTests() : base("dpop", opt =>
    {
        opt.DPoPJsonWebKey = _privateJWK;
    }){}

    [Fact]
    public async Task dpop_jtk_is_attached_to_authorize_requests()
    {
        await AppHost.InitializeAsync();
        await AppHost.LoginAsync("alice", verifyDpopThumbprintSent: true);
    }

    [Fact]
    public async Task dpop_token_refresh_should_succeed()
    {
        await AppHost.InitializeAsync();
        await AppHost.LoginAsync("alice");

        // The DPoP proof token is valid for 1 second, and that validity is checked with the server nonce.
        // We have to wait 2 seconds to make sure our previous (from the initial login) nonce is no longer
        // valid. Ideally we would verify that we actually retried, but in this test we aren't mocking
        // the http client so there isn't an obvious way to do that. However, the next test 
        // (dpop_nonce_is_respected_during_code_exchange) does exactly that.
        Thread.Sleep(2000);

        // This API call should trigger a refresh, and that refresh request must use a nonce from the server (because the client is configured that way)
        var response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token"));
        var token = await response.Content.ReadFromJsonAsync<UserToken>();

        token.ShouldNotBeNull();
        token.IsError.ShouldBeFalse();
        token.AccessTokenType.ShouldBe("DPoP");
    }

    [Fact]
    public async Task dpop_nonce_is_respected_during_code_exchange()
    {
        var mockHttp = new MockHttpMessageHandler(BackendDefinitionBehavior.Always);
        AppHost.IdentityServerHttpHandler = mockHttp;

        // Initial login request 
        var initialTokenResponse = new
        {
            id_token = IdentityServerHost.CreateIdToken("1", "dpop"),
            access_token = "initial_access_token",
            expires_in = 10,
            refresh_token = "initial_refresh_token",
        };
        mockHttp.When("/connect/token")
            .WithFormData("grant_type", "authorization_code")
            .Respond("application/json", JsonSerializer.Serialize(initialTokenResponse));

        // First refresh token request - no nonce
        var nonceResponse = new
        {
            error = "invalid_dpop_proof",
            error_description = "Invalid 'nonce' value.",
        };
        var nonce = "server-provided-nonce";
        mockHttp.Expect("/connect/token")
            .WithFormData("grant_type", "refresh_token")
            .Respond(HttpStatusCode.BadRequest, headers: new Dictionary<string, string>
            {
                { OidcConstants.HttpHeaders.DPoPNonce, nonce }
            },
            "application/json", JsonSerializer.Serialize(nonceResponse));

        // Second refresh request
        var tokenResponse = new
        {
            id_token = IdentityServerHost.CreateIdToken("1", "dpop"),
            access_token = "access_token",
            token_type = "DPoP",
            expires_in = 3600,
            refresh_token = "refresh_token",
        };
        mockHttp.Expect("/connect/token")
            .WithFormData("grant_type", "refresh_token")
            .With(request =>
            {
                var dpopProof = request.Headers.GetValues("DPoP").SingleOrDefault();
                var payload = dpopProof?.Split('.')[1];
                var decodedPayload = Base64UrlEncoder.Decode(payload);
                return decodedPayload.Contains($"\"nonce\":\"{nonce}\"");
            })
            .Respond("application/json", JsonSerializer.Serialize(tokenResponse));


        await AppHost.InitializeAsync();
        await AppHost.LoginAsync("alice");

        // This API call triggers a refresh
        var response = await AppHost.BrowserClient.GetAsync(AppHost.Url("/user_token"));
        var token = await response.Content.ReadFromJsonAsync<UserToken>();
        token.ShouldNotBeNull();
        token.IsError.ShouldBeFalse();
        token.AccessTokenType.ShouldBe("DPoP");
        mockHttp.VerifyNoOutstandingExpectation();
    }
}