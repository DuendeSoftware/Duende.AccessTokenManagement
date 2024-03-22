// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <summary>
/// Delegating handler that injects the DPoP proof token. This is intended to be
/// used on the OIDC authentication handler's backchannel http client.
/// </summary>
public class DPoPProofTokenHandler : DelegatingHandler
{
    private readonly IDPoPProofService _dPoPProofService;
    private readonly IDPoPNonceStore _dPoPNonceStore;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ILogger<DPoPProofTokenHandler> _logger;

    internal DPoPProofTokenHandler(
        IDPoPProofService dPoPProofService,
        IDPoPNonceStore dPoPNonceStore,
        IHttpContextAccessor httpContextAccessor,
        ILogger<DPoPProofTokenHandler> logger)
    {
        _dPoPProofService = dPoPProofService;
        _dPoPNonceStore = dPoPNonceStore;
        _httpContextAccessor = httpContextAccessor;
        _logger = logger;
    }

    /// <inheritdoc/>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        await SetDPoPProofTokenAsync(request, cancellationToken).ConfigureAwait(false);
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        // The authorization server might send us a new nonce in a successful
        // request, indicating that we should use the new nonce in future.
        var dPoPNonce = response.GetDPoPNonce();

        if (dPoPNonce != null)
        {
            _logger.LogDebug("The authorization server has supplied a new nonce");

            await _dPoPNonceStore.StoreNonceAsync(new DPoPNonceContext
            {
                Url = request.GetDPoPUrl(),
                Method = request.Method.ToString(),
            }, dPoPNonce);

            // But the authorization server might also send a failure response, and expect us to retry 
            if (response.StatusCode == System.Net.HttpStatusCode.BadRequest)
            {

                // REVIEW: Is it good enough to check the status code and
                // existence of the new nonce? Should we parse the response, and
                // look for the "use_dpop_nonce" value in the error property?

                _logger.LogDebug("Request failed (bad request). Retrying request with new DPoP proof token that includes the new nonce");
                response.Dispose();
                await SetDPoPProofTokenAsync(request, cancellationToken, dPoPNonce).ConfigureAwait(false);
                return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
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
