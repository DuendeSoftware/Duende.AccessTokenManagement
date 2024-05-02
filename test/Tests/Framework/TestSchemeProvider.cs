// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Duende.AccessTokenManagement.Tests;

public class TestSchemeProvider : IAuthenticationSchemeProvider
{
    public TestSchemeProvider(string signInSchemeName = "testScheme")
    {
        DefaultSignInScheme = new AuthenticationScheme(signInSchemeName, signInSchemeName, typeof(CookieAuthenticationHandler));
    }

    public AuthenticationScheme? DefaultSignInScheme { get; set; }

    public Task<AuthenticationScheme?> GetDefaultSignInSchemeAsync()
    {
        return Task.FromResult(DefaultSignInScheme);
    }

    #region Not Implemented (No tests have needed these yet)

    public void AddScheme(AuthenticationScheme scheme)
    {
        throw new NotImplementedException();
    }

    public Task<IEnumerable<AuthenticationScheme>> GetAllSchemesAsync()
    {
        throw new NotImplementedException();
    }

    public Task<AuthenticationScheme?> GetDefaultAuthenticateSchemeAsync()
    {
        throw new NotImplementedException();
    }

    public Task<AuthenticationScheme?> GetDefaultChallengeSchemeAsync()
    {
        throw new NotImplementedException();
    }

    public Task<AuthenticationScheme?> GetDefaultForbidSchemeAsync()
    {
        throw new NotImplementedException();
    }


    public Task<AuthenticationScheme?> GetDefaultSignOutSchemeAsync()
    {
        throw new NotImplementedException();
    }

    public Task<IEnumerable<AuthenticationScheme>> GetRequestHandlerSchemesAsync()
    {
        throw new NotImplementedException();
    }

    public Task<AuthenticationScheme?> GetSchemeAsync(string name)
    {
        throw new NotImplementedException();
    }

    public void RemoveScheme(string name)
    {
        throw new NotImplementedException();
    }

    #endregion
}
