// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace Duende.TokenManagement.OpenIdConnect
{
    /// <summary>
    /// Delegating handler that injects the current access token into an outgoing request
    /// </summary>
    public class UserAccessTokenHandler : DelegatingHandler
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly UserAccessTokenRequestParameters _parameters;

        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="httpContextAccessor"></param>
        /// <param name="parameters"></param>
        public UserAccessTokenHandler(IHttpContextAccessor httpContextAccessor, UserAccessTokenRequestParameters? parameters = null)
        {
            _httpContextAccessor = httpContextAccessor;
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
              
            var token = await _httpContextAccessor!.HttpContext!.GetUserAccessTokenAsync(parameters);

            if (!string.IsNullOrWhiteSpace(token.Value))
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Value);
            }
        }
    }
}