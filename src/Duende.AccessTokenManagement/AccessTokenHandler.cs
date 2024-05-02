// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel.Client;
using Microsoft.Extensions.Logging;
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
    private readonly ILogger _logger;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="dPoPProofService"></param>
    /// <param name="dPoPNonceStore"></param>
    /// <param name="logger"></param>
    public AccessTokenHandler(
        IDPoPProofService dPoPProofService,
        IDPoPNonceStore dPoPNonceStore,
        ILogger logger)
    {
        _dPoPProofService = dPoPProofService;
        _dPoPNonceStore = dPoPNonceStore;
        _logger = logger;
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
            var force = !response.IsDPoPError();
            if (!force && !string.IsNullOrEmpty(dPoPNonce))
            {
                _logger.LogDebug("DPoP nonce error invoking endpoint: {url}, retrying using new nonce", request.RequestUri?.AbsoluteUri.ToString());
            }

            await SetTokenAsync(request, forceRenewal: force, cancellationToken, dPoPNonce).ConfigureAwait(false);
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
    /// Set an access token on the HTTP request
    /// </summary>
    /// <returns></returns>
    protected virtual async Task SetTokenAsync(HttpRequestMessage request, bool forceRenewal, CancellationToken cancellationToken, string? dpopNonce = null)
    {
        var token = await GetAccessTokenAsync(forceRenewal, cancellationToken).ConfigureAwait(false);
        
        if (!string.IsNullOrWhiteSpace(token?.AccessToken))
        {
            _logger.LogDebug("Sending access token in request to endpoint: {url}", request.RequestUri?.AbsoluteUri.ToString());

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

            // since AccessTokenType above in the token endpoint response (the token_type value) could be case insensitive, but
            // when we send it as an Authorization header in the API request it must be case sensitive, we 
            // are checking for that here and forcing it to the exact casing required.
            if (scheme.Equals(AuthenticationSchemes.AuthorizationHeaderBearer, System.StringComparison.OrdinalIgnoreCase))
            {
                scheme = AuthenticationSchemes.AuthorizationHeaderBearer;
            }
            else if (scheme.Equals(AuthenticationSchemes.AuthorizationHeaderDPoP, System.StringComparison.OrdinalIgnoreCase))
            {
                scheme = AuthenticationSchemes.AuthorizationHeaderDPoP;
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
                Url = request.GetDPoPUrl(),
                Method = request.Method.ToString(),
                DPoPJsonWebKey = token.DPoPJsonWebKey,
                DPoPNonce = dpopNonce,
            });

            if (proofToken != null)
            {
                _logger.LogDebug("Sending DPoP proof token in request to endpoint: {url}", request.RequestUri?.AbsoluteUri.ToString());

                request.SetDPoPProofToken(proofToken.ProofToken);
                return true;
            }
            else
            {
                _logger.LogDebug("No DPoP proof token in request to endpoint: {url}", request.RequestUri?.AbsoluteUri.ToString());
            }
        }

        return false;
    }
}