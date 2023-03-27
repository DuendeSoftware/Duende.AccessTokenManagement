// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel.Client;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using static IdentityModel.OidcConstants;

namespace Duende.AccessTokenManagement;

/// <summary>
/// Delegating handler that injects access token into an outgoing request
/// </summary>
public abstract class AccessTokenHandler : DelegatingHandler
{
    private readonly IDPoPProofService _dPoPProofService;
    private readonly IDPoPNonceStore _dPoPNonceStore;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="dPoPProofService"></param>
    /// <param name="dPoPNonceStore"></param>
    public AccessTokenHandler(
        IDPoPProofService dPoPProofService,
        IDPoPNonceStore dPoPNonceStore)
    {
        _dPoPProofService = dPoPProofService;
        _dPoPNonceStore = dPoPNonceStore;
    }

    /// <summary>
    /// Returns the access token for the outbound call.
    /// </summary>
    /// <param name="forceRenewal"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    protected abstract Task<ClientCredentialsToken> GetAccessTokenAsync(bool forceRenewal, CancellationToken cancellationToken);

    /// <inheritdoc/>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        await SetTokenAsync(request, forceRenewal: false, cancellationToken).ConfigureAwait(false);
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var dPoPNonce = response.GetDPoPNonce();

        // retry if 401
        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            response.Dispose();

            // if it's a DPoP nonce error, we don't need to obtain a new access token
            var force = response.IsDPoPNonceError();

            await SetTokenAsync(request, forceRenewal: force, cancellationToken, dPoPNonce).ConfigureAwait(false);
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        else if (dPoPNonce != null)
        {
            await _dPoPNonceStore.StoreNonceAsync(new DPoPNonceContext
            {
                Url = request.RequestUri!.AbsoluteUri,
                Method = request.Method.ToString(),
            }, dPoPNonce);
        }

        return response;
    }

    /// <summary>
    /// Set an access token on the HTTP request
    /// </summary>
    /// <returns></returns>
    protected virtual async Task SetTokenAsync(HttpRequestMessage request, bool forceRenewal, CancellationToken cancellationToken, string? dpopNonce = null)
    {
        var token = await GetAccessTokenAsync(forceRenewal, cancellationToken).ConfigureAwait(false);
        
        if (!string.IsNullOrWhiteSpace(token?.AccessToken))
        {
            var scheme = token.AccessTokenType ?? AuthenticationSchemes.AuthorizationHeaderBearer;

            if (!string.IsNullOrWhiteSpace(token.DPoPJsonWebKey))
            {
                // looks like this is a DPoP bound token, so try to generate the proof token
                if (!await SetDPoPProofTokenAsync(request, token, cancellationToken, dpopNonce))
                {
                    // failed or opted out for this request, to fall back to Bearer 
                    scheme = AuthenticationSchemes.AuthorizationHeaderBearer;
                }
            }

            // checking for null AccessTokenType and falling back to "Bearer" since this might be coming
            // from an old cache/store prior to adding the AccessTokenType property.
            request.SetToken(scheme, token.AccessToken);
        }
    }

    /// <summary>
    /// Creates a DPoP proof token and attaches it to the request.
    /// </summary>
    protected virtual async Task<bool> SetDPoPProofTokenAsync(HttpRequestMessage request, ClientCredentialsToken token, CancellationToken cancellationToken, string? dpopNonce = null)
    {
        // remove any old headers
        request.ClearDPoPProofToken();

        if (!string.IsNullOrEmpty(token.DPoPJsonWebKey))
        {
            // create proof
            var proofToken = await _dPoPProofService.CreateProofTokenAsync(new DPoPProofRequest
            {
                AccessToken = token.AccessToken,
                Url = request.RequestUri!.AbsoluteUri,
                Method = request.Method.ToString(),
                DPoPJsonWebKey = token.DPoPJsonWebKey,
                DPoPNonce = dpopNonce,
            });

            if (proofToken != null)
            {
                request.SetDPoPProofToken(proofToken.ProofToken);
                return true;
            }
        }

        return false;
    }
}