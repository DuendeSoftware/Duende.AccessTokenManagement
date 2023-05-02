// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <summary>
/// Delegating handler that injects the DPoP proof token from the OIDC handler workflow
/// </summary>
class DPoPProofTokenHandler : DelegatingHandler
{
    private readonly IDPoPProofService _dPoPProofService;
    private readonly IDPoPNonceStore _dPoPNonceStore;
    private readonly IHttpContextAccessor _httpContextAccessor;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="dPoPProofService"></param>
    /// <param name="dPoPNonceStore"></param>
    /// <param name="httpContextAccessor"></param>
    public DPoPProofTokenHandler(
        IDPoPProofService dPoPProofService,
        IDPoPNonceStore dPoPNonceStore,
        IHttpContextAccessor httpContextAccessor)
    {
        _dPoPProofService = dPoPProofService;
        _dPoPNonceStore = dPoPNonceStore;
        _httpContextAccessor = httpContextAccessor;
    }

    /// <inheritdoc/>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        await SetDPoPProofTokenAsync(request, cancellationToken).ConfigureAwait(false);
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var dPoPNonce = response.GetDPoPNonce();

        // retry if 401
        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized && response.IsDPoPNonceError())
        {
            response.Dispose();

            await SetDPoPProofTokenAsync(request, cancellationToken, dPoPNonce).ConfigureAwait(false);
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        else if (dPoPNonce != null)
        {
            await _dPoPNonceStore.StoreNonceAsync(new DPoPNonceContext
            {
                Url = request.GetDPoPUrl(),
                Method = request.Method.ToString(),
            }, dPoPNonce);
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
                request.SetDPoPProofToken(proofToken.ProofToken);
            }
        }
    }
}
