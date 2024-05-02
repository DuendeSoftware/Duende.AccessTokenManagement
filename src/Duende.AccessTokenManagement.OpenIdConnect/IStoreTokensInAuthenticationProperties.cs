// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <summary>
/// Interface that encapsulates the logic of storing UserTokens in AuthenticationProperties
/// </summary>
public interface IStoreTokensInAuthenticationProperties
{
    /// <summary>
    /// Gets a UserToken from the AuthenticationProperties
    /// </summary>
    UserToken GetUserToken(AuthenticationProperties authenticationProperties, UserTokenRequestParameters? parameters = null);
    
    /// <summary>
    /// Sets a UserToken in the AuthenticationProperties.
    /// </summary>
    void SetUserToken(UserToken token, AuthenticationProperties authenticationProperties, UserTokenRequestParameters? parameters = null);
    
    /// <summary>
    /// Removes a UserToken from the AuthenticationProperties.
    /// </summary>
    /// <param name="authenticationProperties"></param>
    /// <param name="parameters"></param>
    void RemoveUserToken(AuthenticationProperties authenticationProperties, UserTokenRequestParameters? parameters = null);
    
    /// <summary>
    /// Gets the scheme name used when storing a UserToken in an
    /// AuthenticationProperties.
    /// </summary>
    Task<string> GetSchemeAsync(UserTokenRequestParameters? parameters = null);
}
