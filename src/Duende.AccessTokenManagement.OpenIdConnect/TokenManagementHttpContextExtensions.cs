// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Threading;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Threading.Tasks;
using Duende.AccessTokenManagement;
using Duende.AccessTokenManagement.OpenIdConnect;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Authentication;

/// <summary>
/// Extensions methods for HttpContext for token management
/// </summary>
public static class TokenManagementHttpContextExtensions
{
    /// <summary>
    /// Returns (and refreshes if needed) the current access token for the logged on user
    /// </summary>
    /// <param name="httpContext">The HTTP context</param>
    /// <param name="parameters">Extra optional parameters</param>
    /// <param name="cancellationToken">A cancellation token to cancel operation.</param>
    /// <returns></returns>
    public static async Task<UserAccessToken> GetUserAccessTokenAsync(
        this HttpContext httpContext,
        UserAccessTokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        var service = httpContext.RequestServices.GetRequiredService<IUserTokenManagementService>();

        return await service.GetAccessTokenAsync(httpContext.User, parameters, cancellationToken);
    }

    /// <summary>
    /// Revokes the current user refresh token
    /// </summary>
    /// <param name="httpContext">The HTTP context</param>
    /// <param name="parameters">Extra optional parameters</param>
    /// <param name="cancellationToken">A cancellation token to cancel operation.</param>
    /// <returns></returns>
    public static async Task RevokeRefreshTokenAsync(
        this HttpContext httpContext,
        UserAccessTokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        var service = httpContext.RequestServices.GetRequiredService<IUserTokenManagementService>();
        var store = httpContext.RequestServices.GetRequiredService<IUserTokenStore>();

        await service.RevokeRefreshTokenAsync(httpContext.User, parameters, cancellationToken);
        
        // todo: is this the right place to call that - or should revoke do that?
        await store.ClearTokenAsync(httpContext.User, parameters);
    }
    
    /// <summary>
    /// Returns an access token for the OpenID Connect client using client credentials flow
    /// </summary>
    /// <param name="httpContext">The HTTP context</param>
    /// <param name="parameters">Extra optional parameters</param>
    /// <param name="cancellationToken">A cancellation token to cancel operation.</param>
    /// <returns></returns>
    public static async Task<ClientCredentialsToken> GetClientAccessTokenAsync(
        this HttpContext httpContext,
        UserAccessTokenRequestParameters? parameters = null,
        CancellationToken cancellationToken = default)
    {
        var service = httpContext.RequestServices.GetRequiredService<IClientCredentialsTokenManagementService>();
        var options = httpContext.RequestServices.GetRequiredService<IOptions<UserAccessTokenManagementOptions>>();
        var schemes = httpContext.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>();

        var schemeName = parameters?.ChallengeScheme ?? options.Value.ChallengeScheme;
        
        if (string.IsNullOrEmpty(schemeName))
        {
            var defaultScheme = await schemes.GetDefaultChallengeSchemeAsync();
            ArgumentNullException.ThrowIfNull(defaultScheme);

            schemeName = defaultScheme.Name;
        }

        return await service.GetAccessTokenAsync(
            OpenIdConnectTokenManagementDefaults.ClientCredentialsClientNamePrefix + schemeName,
            parameters, 
            cancellationToken);
    }
}