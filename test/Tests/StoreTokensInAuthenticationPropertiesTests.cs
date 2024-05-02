// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Duende.AccessTokenManagement.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Logging.Abstractions;

namespace Duende.AccessTokenManagement.Tests;

public class StoreTokensInAuthenticationPropertiesTests
{
    [Fact]
    public void Should_be_able_to_store_and_retrieve_tokens()
    {
        var authenticationProperties = new AuthenticationProperties();
        var sut = new StoreTokensInAuthenticationProperties(
            new TestOptionsMonitor<UserTokenManagementOptions>(),
            new TestOptionsMonitor<CookieAuthenticationOptions>(),
            new TestSchemeProvider(),
            new NullLogger<StoreTokensInAuthenticationProperties>()
        );

        var userToken = GenerateRandomUserToken();

        sut.SetUserToken(userToken, authenticationProperties);
        var result = sut.GetUserToken(authenticationProperties);

        result.ShouldBeEquivalentTo(userToken);
    }

    [Fact]
    public void Should_be_able_to_store_and_retrieve_tokens_for_multiple_challenge_schemes()
    {
        var authenticationProperties = new AuthenticationProperties();
        var sut = new StoreTokensInAuthenticationProperties(
            new TestOptionsMonitor<UserTokenManagementOptions>(new UserTokenManagementOptions
            {
                UseChallengeSchemeScopedTokens = true
            }),
            new TestOptionsMonitor<CookieAuthenticationOptions>(),
            new TestSchemeProvider(),
            new NullLogger<StoreTokensInAuthenticationProperties>()
        );

        var tokenForScheme1 = GenerateRandomUserToken();
        var tokenForScheme2 = GenerateRandomUserToken();

        var scheme1RequestParameters = new UserTokenRequestParameters
        {
            ChallengeScheme = "scheme1"
        };
        var scheme2RequestParameters = new UserTokenRequestParameters
        {
            ChallengeScheme = "scheme2"
        };

        sut.SetUserToken(tokenForScheme1, authenticationProperties, scheme1RequestParameters);
        sut.SetUserToken(tokenForScheme2, authenticationProperties, scheme2RequestParameters);

        var resultScheme1 = sut.GetUserToken(authenticationProperties, scheme1RequestParameters);
        var resultScheme2 = sut.GetUserToken(authenticationProperties, scheme2RequestParameters);

        resultScheme1.ShouldBeEquivalentTo(tokenForScheme1);
        resultScheme2.ShouldBeEquivalentTo(tokenForScheme2);
    }

    [Fact]
    public void Should_be_able_to_store_and_retrieve_tokens_for_multiple_resources()
    {
        var authenticationProperties = new AuthenticationProperties();
        var sut = new StoreTokensInAuthenticationProperties(
            new TestOptionsMonitor<UserTokenManagementOptions>(),
            new TestOptionsMonitor<CookieAuthenticationOptions>(),
            new TestSchemeProvider(),
            new NullLogger<StoreTokensInAuthenticationProperties>()
        );

        var tokenForResource1 = GenerateRandomUserToken();
        var tokenForResource2 = GenerateAnotherTokenForADifferentResource(tokenForResource1);

        var resource1RequestParameters = new UserTokenRequestParameters
        {
            Resource = "resource1",
        };
        var resource2RequestParameters = new UserTokenRequestParameters
        {
            Resource = "resource2",
        };

        sut.SetUserToken(tokenForResource1, authenticationProperties, resource1RequestParameters);
        sut.SetUserToken(tokenForResource2, authenticationProperties, resource2RequestParameters);

        var resultForResource1 = sut.GetUserToken(authenticationProperties, resource1RequestParameters);
        var resultForResource2 = sut.GetUserToken(authenticationProperties, resource2RequestParameters);

        resultForResource1.ShouldBeEquivalentTo(tokenForResource1);
        resultForResource2.ShouldBeEquivalentTo(tokenForResource2);
    }

    [Fact]
    public void Should_be_able_to_store_and_retrieve_tokens_for_multiple_schemes_and_resources_at_the_same_time()
    {
        var authenticationProperties = new AuthenticationProperties();
        var sut = new StoreTokensInAuthenticationProperties(
            new TestOptionsMonitor<UserTokenManagementOptions>(new UserTokenManagementOptions
            {
                UseChallengeSchemeScopedTokens = true
            }),
            new TestOptionsMonitor<CookieAuthenticationOptions>(),
            new TestSchemeProvider(),
            new NullLogger<StoreTokensInAuthenticationProperties>()
        );

        var tokenForResource1Scheme1 = GenerateRandomUserToken();
        var tokenForResource1Scheme2 = GenerateRandomUserToken();
        var tokenForResource2Scheme1 = GenerateAnotherTokenForADifferentResource(tokenForResource1Scheme1);
        var tokenForResource2Scheme2 = GenerateAnotherTokenForADifferentResource(tokenForResource1Scheme2);

        var resource1Scheme1 = new UserTokenRequestParameters
        {
            Resource = "resource1",
            ChallengeScheme = "scheme1"
        };

        var resource1Scheme2 = new UserTokenRequestParameters
        {
            Resource = "resource1",
            ChallengeScheme = "scheme2"
        };

        var resource2Scheme1 = new UserTokenRequestParameters
        {
            Resource = "resource2",
            ChallengeScheme = "scheme1"
        };

        var resource2Scheme2 = new UserTokenRequestParameters
        {
            Resource = "resource2",
            ChallengeScheme = "scheme2"
        };

        sut.SetUserToken(tokenForResource1Scheme1, authenticationProperties, resource1Scheme1);
        sut.SetUserToken(tokenForResource1Scheme2, authenticationProperties, resource1Scheme2);
        sut.SetUserToken(tokenForResource2Scheme1, authenticationProperties, resource2Scheme1);
        sut.SetUserToken(tokenForResource2Scheme2, authenticationProperties, resource2Scheme2);

        var resultForResource1Scheme1 = sut.GetUserToken(authenticationProperties, resource1Scheme1);
        var resultForResource1Scheme2 = sut.GetUserToken(authenticationProperties, resource1Scheme2);
        var resultForResource2Scheme1 = sut.GetUserToken(authenticationProperties, resource2Scheme1);
        var resultForResource2Scheme2 = sut.GetUserToken(authenticationProperties, resource2Scheme2);

        resultForResource1Scheme1.ShouldBeEquivalentTo(tokenForResource1Scheme1);
        resultForResource1Scheme2.ShouldBeEquivalentTo(tokenForResource1Scheme2);
        resultForResource2Scheme1.ShouldBeEquivalentTo(tokenForResource2Scheme1);
        resultForResource2Scheme2.ShouldBeEquivalentTo(tokenForResource2Scheme2);
    }

    [Fact]
    public void Should_be_able_to_remove_tokens()
    {
        var authenticationProperties = new AuthenticationProperties();
        var sut = new StoreTokensInAuthenticationProperties(
            new TestOptionsMonitor<UserTokenManagementOptions>(),
            new TestOptionsMonitor<CookieAuthenticationOptions>(),
            new TestSchemeProvider(),
            new NullLogger<StoreTokensInAuthenticationProperties>()
        );

        var userToken = GenerateRandomUserToken();

        sut.SetUserToken(userToken, authenticationProperties);
        sut.RemoveUserToken(authenticationProperties);
        var result = sut.GetUserToken(authenticationProperties);

        result.AccessToken.ShouldBeNull();
        result.AccessTokenType.ShouldBeNull();
        result.DPoPJsonWebKey.ShouldBeNull();
        result.RefreshToken.ShouldBeNull();
        result.Expiration.ShouldBe(default);
    }


    [Fact]
    public void Should_be_able_to_remove_tokens_for_multiple_schemes_and_resources_at_the_same_time()
    {
        var authenticationProperties = new AuthenticationProperties();
        var sut = new StoreTokensInAuthenticationProperties(
            new TestOptionsMonitor<UserTokenManagementOptions>(new UserTokenManagementOptions
            {
                UseChallengeSchemeScopedTokens = true
            }),
            new TestOptionsMonitor<CookieAuthenticationOptions>(),
            new TestSchemeProvider(),
            new NullLogger<StoreTokensInAuthenticationProperties>()
        );

        var tokenForResource1Scheme1 = GenerateRandomUserToken();
        var tokenForResource1Scheme2 = GenerateRandomUserToken();
        var tokenForResource2Scheme1 = GenerateAnotherTokenForADifferentResource(tokenForResource1Scheme1);
        var tokenForResource2Scheme2 = GenerateAnotherTokenForADifferentResource(tokenForResource1Scheme2);

        var resource1Scheme1 = new UserTokenRequestParameters
        {
            Resource = "resource1",
            ChallengeScheme = "scheme1"
        };

        var resource1Scheme2 = new UserTokenRequestParameters
        {
            Resource = "resource1",
            ChallengeScheme = "scheme2"
        };

        var resource2Scheme1 = new UserTokenRequestParameters
        {
            Resource = "resource2",
            ChallengeScheme = "scheme1"
        };

        var resource2Scheme2 = new UserTokenRequestParameters
        {
            Resource = "resource2",
            ChallengeScheme = "scheme2"
        };

        sut.SetUserToken(tokenForResource1Scheme1, authenticationProperties, resource1Scheme1);
        sut.SetUserToken(tokenForResource1Scheme2, authenticationProperties, resource1Scheme2);
        sut.SetUserToken(tokenForResource2Scheme1, authenticationProperties, resource2Scheme1);
        sut.SetUserToken(tokenForResource2Scheme2, authenticationProperties, resource2Scheme2);

        sut.RemoveUserToken(authenticationProperties, resource1Scheme1);
        sut.RemoveUserToken(authenticationProperties, resource2Scheme2);

        var resultForResource1Scheme1 = sut.GetUserToken(authenticationProperties, resource1Scheme1);
        var resultForResource1Scheme2 = sut.GetUserToken(authenticationProperties, resource1Scheme2);
        var resultForResource2Scheme1 = sut.GetUserToken(authenticationProperties, resource2Scheme1);
        var resultForResource2Scheme2 = sut.GetUserToken(authenticationProperties, resource2Scheme2);

        resultForResource1Scheme1.AccessToken.ShouldBeNull();
        resultForResource1Scheme2.ShouldBeEquivalentTo(tokenForResource1Scheme2);
        resultForResource2Scheme1.ShouldBeEquivalentTo(tokenForResource2Scheme1);
        resultForResource2Scheme2.AccessToken.ShouldBeNull();
    }


    [Fact]
    public void Removing_all_tokens_in_a_challenge_scheme_should_remove_items_shared_in_that_scheme()
    {
        var authenticationProperties = new AuthenticationProperties();
        var sut = new StoreTokensInAuthenticationProperties(
            new TestOptionsMonitor<UserTokenManagementOptions>(new UserTokenManagementOptions
            {
                UseChallengeSchemeScopedTokens = true
            }),
            new TestOptionsMonitor<CookieAuthenticationOptions>(),
            new TestSchemeProvider(),
            new NullLogger<StoreTokensInAuthenticationProperties>()
        );

        var tokenForResource1Scheme1 = GenerateRandomUserToken();
        var tokenForResource1Scheme2 = GenerateRandomUserToken();
        var tokenForResource2Scheme1 = GenerateAnotherTokenForADifferentResource(tokenForResource1Scheme1);
        var tokenForResource2Scheme2 = GenerateAnotherTokenForADifferentResource(tokenForResource1Scheme2);

        var resource1Scheme1 = new UserTokenRequestParameters
        {
            Resource = "resource1",
            ChallengeScheme = "scheme1"
        };

        var resource1Scheme2 = new UserTokenRequestParameters
        {
            Resource = "resource1",
            ChallengeScheme = "scheme2"
        };

        var resource2Scheme1 = new UserTokenRequestParameters
        {
            Resource = "resource2",
            ChallengeScheme = "scheme1"
        };

        var resource2Scheme2 = new UserTokenRequestParameters
        {
            Resource = "resource2",
            ChallengeScheme = "scheme2"
        };

        sut.SetUserToken(tokenForResource1Scheme1, authenticationProperties, resource1Scheme1);
        sut.SetUserToken(tokenForResource1Scheme2, authenticationProperties, resource1Scheme2);
        sut.SetUserToken(tokenForResource2Scheme1, authenticationProperties, resource2Scheme1);
        sut.SetUserToken(tokenForResource2Scheme2, authenticationProperties, resource2Scheme2);

        sut.RemoveUserToken(authenticationProperties, resource1Scheme1);
        sut.RemoveUserToken(authenticationProperties, resource1Scheme2);
        sut.RemoveUserToken(authenticationProperties, resource2Scheme1);
        sut.RemoveUserToken(authenticationProperties, resource2Scheme2);

        var resultForResource1Scheme1 = sut.GetUserToken(authenticationProperties, resource1Scheme1);
        resultForResource1Scheme1.RefreshToken.ShouldBeNull();
        resultForResource1Scheme1.DPoPJsonWebKey.ShouldBeNull();
    }

    private UserToken GenerateRandomUserToken() => new UserToken
    {
        AccessToken = Guid.NewGuid().ToString(),
        AccessTokenType = Guid.NewGuid().ToString(),
        RefreshToken = Guid.NewGuid().ToString(),
        Expiration = new DateTimeOffset(new DateTime(Random.Shared.Next())),
        DPoPJsonWebKey = Guid.NewGuid().ToString()
    };

    private UserToken GenerateAnotherTokenForADifferentResource(UserToken previousToken) => new UserToken
    {
        AccessToken = Guid.NewGuid().ToString(),
        AccessTokenType = Guid.NewGuid().ToString(),
        Expiration = new DateTimeOffset(new DateTime(Random.Shared.Next())),

        // These two values don't change when we switch resources
        RefreshToken = previousToken.RefreshToken,
        DPoPJsonWebKey = previousToken.DPoPJsonWebKey,
    };
}
