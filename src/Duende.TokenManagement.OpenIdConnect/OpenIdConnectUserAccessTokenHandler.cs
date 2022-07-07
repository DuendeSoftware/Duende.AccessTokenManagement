// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace Duende.TokenManagement.OpenIdConnect;

/// <summary>
/// Delegating handler that injects the current access token into an outgoing request
/// </summary>
public class OpenIdConnectUserAccessTokenHandler : DelegatingHandler
{
    private readonly IUserTokenManagementService _userTokenManagementService;
    private readonly IUserService _userService;
    private readonly UserAccessTokenRequestParameters _parameters;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="userService"></param>
    /// <param name="parameters"></param>
    /// <param name="userTokenManagementService"></param>
    public OpenIdConnectUserAccessTokenHandler(
        IUserTokenManagementService userTokenManagementService, 
        IUserService userService, 
        UserAccessTokenRequestParameters? parameters = null)
    {
        _userTokenManagementService = userTokenManagementService;
        _userService = userService;
        _parameters = parameters ?? new UserAccessTokenRequestParameters();
    }

    /// <inheritdoc/>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        await SetTokenAsync(request, forceRenewal: false);
        var response = await base.SendAsync(request, cancellationToken);

        // retry if 401
        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            response.Dispose();

            await SetTokenAsync(request, forceRenewal: true);
            return await base.SendAsync(request, cancellationToken);
        }

        return response;
    }

    /// <summary>
    /// Set an access token on the HTTP request
    /// </summary>
    /// <param name="request"></param>
    /// <param name="forceRenewal"></param>
    /// <returns></returns>
    protected virtual async Task SetTokenAsync(HttpRequestMessage request, bool forceRenewal)
    {
        var parameters = new UserAccessTokenRequestParameters
        {
            SignInScheme = _parameters.SignInScheme,
            ChallengeScheme = _parameters.ChallengeScheme,
            Resource = _parameters.Resource,
            ForceRenewal = forceRenewal,
            Context =  _parameters.Context
        };

        var user = _userService.Principal;
        var token = await _userTokenManagementService.GetAccessTokenAsync(user, parameters);
        
        if (!string.IsNullOrWhiteSpace(token.Value))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Value);
        }
    }
}