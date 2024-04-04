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
/// Delegating handler that adds behavior needed for DPoP to the backchannel
/// http client of the OIDC authentication handler.
///
/// This handler has two main jobs:
///
/// 1. Store new nonces from successful responses from the authorization server.
///
/// 2. Attach proof tokens to token requests in the code flow. 
///
///    On the authorize request, we will have sent a dpop_jkt parameter with a
///    key thumbprint. The AS expects that we will use the corresponding key to
///    create our proof, and we track that key in the http context. This handler
///    retrieves that key and uses it to create proof tokens for use in the code
///    flow. 
///
///    Additionally, the token endpoint might respond to a token exchange
///    request with a request to retry with a nonce that it supplies via http
///    header. When it does, this handler retries those code exchange requests.
///
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
        var codeExchangeJwk = _httpContextAccessor.HttpContext?.GetCodeExchangeDPoPKey();
        if (codeExchangeJwk != null)
        {
            await SetDPoPProofTokenForCodeExchangeAsync(request, jwk: codeExchangeJwk).ConfigureAwait(false);
        }

        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        // The authorization server might send us a new nonce on either a success or failure
        var dPoPNonce = response.GetDPoPNonce();

        if (dPoPNonce != null)
        {
            // This handler contains specialized logic to create the new proof
            // token using the proof key that was associated with a code flow
            // using a dpop_jkt parameter on the authorize call. Other flows
            // (such as refresh), are separately responsible for retrying with a
            // server-issued nonce. So, we ONLY do the retry logic when we have
            // the dpop_jkt's jwk
            if (codeExchangeJwk != null)
            {
                // If the http response code indicates a bad request, we can infer
                // that we should retry with the new nonce. 
                //
                // The server should have also set the error: use_dpop_nonce, but
                // there's no need to incur the cost of parsing the json and
                // checking for that, as we would only receive the nonce http header
                // when that error was set. Authorization servers might preemptively
                // send a new nonce, but the spec specifically says to do that on a
                // success (and we handle that case in the else block). 
                //
                // TL;DR - presence of nonce and 400 response code is enough to
                // trigger a retry during code exchange
                if (response.StatusCode == HttpStatusCode.BadRequest)
                {
                    _logger.LogDebug("Token request failed with DPoP nonce error. Retrying with new nonce.");
                    response.Dispose();
                    await SetDPoPProofTokenForCodeExchangeAsync(request, dPoPNonce, codeExchangeJwk).ConfigureAwait(false);
                    return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
                }
            }
            
            if (response.StatusCode == HttpStatusCode.OK)
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
    /// Creates a DPoP proof token and attaches it to a request.
    /// </summary>
    internal async Task SetDPoPProofTokenForCodeExchangeAsync(HttpRequestMessage request, string? dpopNonce = null, string? jwk = null)
    {
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
