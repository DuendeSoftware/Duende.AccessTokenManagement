// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <summary>
/// Accesses the current user from blazor server.  
/// </summary>
public class BlazorServerUserAccessor(
    // We use the CircuitServicesAccessor to resolve the
    // AuthenticationStateProvider, rather than injecting it. Injecting the
    // state provider directly doesn't work here, because this service might be
    // called in a non-blazor DI scope.
    CircuitServicesAccessor circuitServicesAccessor, 
    IHttpContextAccessor? httpContextAccessor,
    ILogger<BlazorServerUserAccessor> logger) : IUserAccessor
{

    /// <inheritdoc/>
    public async Task<ClaimsPrincipal> GetCurrentUserAsync()
    {
        var authStateProvider = circuitServicesAccessor.Services?
            .GetService<AuthenticationStateProvider>();
        // If we are in blazor server (streaming over a circuit), this provider will be non-null
        if (authStateProvider != null)
        {
            var authState = await authStateProvider.GetAuthenticationStateAsync();
            return authState.User;
        }
        // Otherwise, we should be in an SSR scenario, and the httpContext should be available
        else if(httpContextAccessor?.HttpContext != null)
        {
            return httpContextAccessor.HttpContext.User;
        }
        // If we are in neither blazor server or SSR, something weird is going on.
        else
        {
            logger.LogWarning("Neither an authentication state provider or http context are available to obtain the current principal.");
            return new ClaimsPrincipal();
        }
    }

}


