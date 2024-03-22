// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <summary>
/// Delegating handler that injects the DPoP proof token into requests that are
/// made to the authorization server. This is intended to be used on the OIDC
/// authentication handler's backchannel http client.
/// </summary>
internal class AuthorizationServerDPoPHandler : DelegatingHandler
{
    private readonly IDPoPProofService _dPoPProofService;
    private readonly IDPoPNonceStore _dPoPNonceStore;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<AuthorizationServerDPoPHandler> _logger;

    internal AuthorizationServerDPoPHandler(
        IDPoPProofService dPoPProofService,
        IDPoPNonceStore dPoPNonceStore,
        IHttpContextAccessor httpContextAccessor,
        ILoggerFactory loggerFactory)
    {
        _dPoPProofService = dPoPProofService;
        _dPoPNonceStore = dPoPNonceStore;
        _httpContextAccessor = httpContextAccessor;
        // We depend on the logger factory, rather than the logger itself, since
        // the type parameter of the logger (referencing this class) will not
        // always be accessible.
        _logger = loggerFactory.CreateLogger<AuthorizationServerDPoPHandler>();
    }

    /// <inheritdoc/>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        await SetDPoPProofTokenAsync(request, cancellationToken).ConfigureAwait(false);
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        // The authorization server might send us a new nonce on either a success or failure
        var dPoPNonce = response.GetDPoPNonce();

        if (dPoPNonce != null)
        {
            // If the response code is a bad request, we can infer that we
            // should retry with the new nonce. The server should have also set
            // the error: use_dpop_nonce, but there's no need to incur the cost
            // of parsing the json and checking for that, as we would only
            // receive the nonce http header when that error was set.
            // Authorization servers might preemptively send a new nonce, but
            // the spec specifically says to do that on a success (and we handle
            // that case in the else block)
            //
            // TL;DR - presence of nonce and 400 response code is enough to
            // trigger a retry
            if (response.StatusCode == HttpStatusCode.BadRequest)
            {
                _logger.LogDebug("Request failed (bad request). Retrying request with new DPoP proof token that includes the new nonce");
                response.Dispose();
                await SetDPoPProofTokenAsync(request, cancellationToken, dPoPNonce).ConfigureAwait(false);
                return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
            } 
            else if (response.StatusCode == HttpStatusCode.OK)
            {
                _logger.LogDebug("The authorization server has supplied a new nonce on a successful response, which will be stored and used in future requests to the authorization server");

                await _dPoPNonceStore.StoreNonceAsync(new DPoPNonceContext
                {
                    Url = request.GetDPoPUrl(),
                    Method = request.Method.ToString(),
                }, dPoPNonce);
            }
        }

        return response;
    }

    /// <summary>
    /// Creates a DPoP proof token and attaches it to the request.
    /// </summary>
    protected virtual async Task SetDPoPProofTokenAsync(HttpRequestMessage request, CancellationToken cancellationToken, string? dpopNonce = null)
    {
        var jwk = _httpContextAccessor.HttpContext?.GetOutboundProofKey();

        if (!string.IsNullOrEmpty(jwk))
        {
            // remove any old headers
            request.ClearDPoPProofToken();

            // create proof
            var proofToken = await _dPoPProofService.CreateProofTokenAsync(new DPoPProofRequest
            {
                Url = request.GetDPoPUrl(),
                Method = request.Method.ToString(),
                DPoPJsonWebKey = jwk,
                DPoPNonce = dpopNonce,
            });

            if (proofToken != null)
            {
                _logger.LogDebug("Sending DPoP proof token in request to endpoint: {url}", 
                    request.RequestUri?.GetLeftPart(System.UriPartial.Path));
                request.SetDPoPProofToken(proofToken.ProofToken);
            }
            else
            {
                _logger.LogDebug("No DPoP proof token in request to endpoint: {url}", 
                    request.RequestUri?.GetLeftPart(System.UriPartial.Path));
            }
        }
    }
}
