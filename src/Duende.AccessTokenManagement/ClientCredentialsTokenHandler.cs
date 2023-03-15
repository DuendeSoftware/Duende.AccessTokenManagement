// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel;
using System;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace Duende.AccessTokenManagement;

/// <summary>
/// Delegating handler that injects a client credentials access token into an outgoing request
/// </summary>
public class ClientCredentialsTokenHandler : DelegatingHandler
{
    private readonly IClientCredentialsTokenManagementService _accessTokenManagementService;
    private readonly IDPoPProofService _dPoPProofService;
    private readonly IDPoPNonceStore _dPoPNonceStore;
    private readonly string _tokenClientName;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="accessTokenManagementService">The Access Token Management Service</param>
    /// <param name="dPoPProofService"></param>
    /// <param name="dPoPNonceStore"></param>
    /// <param name="tokenClientName">The name of the token client configuration</param>
    public ClientCredentialsTokenHandler(
        IClientCredentialsTokenManagementService accessTokenManagementService,
        IDPoPProofService dPoPProofService,
        IDPoPNonceStore dPoPNonceStore,
        string tokenClientName)
    {
        _accessTokenManagementService = accessTokenManagementService;
        _dPoPProofService = dPoPProofService;
        _dPoPNonceStore = dPoPNonceStore;
        _tokenClientName = tokenClientName;
    }

    /// <inheritdoc/>
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        await SetTokenAsync(request, forceRenewal: false, cancellationToken).ConfigureAwait(false);
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var dPoPNonce = GetDPoPNonce(response);

        // retry if 401
        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            response.Dispose();

            // if it's a DPoP nonce error, we don't need to obtain a new access token
            var force = IsDPoPNonceError(response);

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

    private string? GetDPoPNonce(HttpResponseMessage response)
    {
        var nonce = response.Headers.FirstOrDefault(x => x.Key == OidcConstants.HttpHeaders.DPoPNonce).Value.FirstOrDefault();
        return nonce;
    }

    private bool IsDPoPNonceError(HttpResponseMessage response)
    {
        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            var header = response.Headers.WwwAuthenticate.Where(x => x.Scheme == OidcConstants.AuthenticationSchemes.AuthorizationHeaderDPoP).FirstOrDefault();
            if (header != null && header.Parameter != null)
            {
                // WWW-Authenticate: DPoP error="use_dpop_nonce"
                var values = header.Parameter.Split(',', StringSplitOptions.RemoveEmptyEntries);
                var error = values.Select(x =>
                {
                    var parts = x.Split('=', StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length == 2 && parts[0] == OidcConstants.TokenResponse.Error)
                    {
                        return parts[1];
                    }
                    return null;
                }).Where(x => x != null).FirstOrDefault();

                return error == OidcConstants.TokenErrors.UseDPoPNonce;
            }
        }

        return false;
    }

    /// <summary>
    /// Set an access token on the HTTP request
    /// </summary>
    /// <returns></returns>
    protected virtual async Task SetTokenAsync(HttpRequestMessage request, bool forceRenewal, CancellationToken cancellationToken, string? dpopNonce = null)
    {
        var parameters = new TokenRequestParameters
        {
            ForceRenewal = forceRenewal
        };

        var token = await _accessTokenManagementService.GetAccessTokenAsync(_tokenClientName, parameters: parameters, cancellationToken: cancellationToken).ConfigureAwait(false);

        if (!string.IsNullOrWhiteSpace(token.AccessToken))
        {
            var scheme = token.AccessTokenType ?? "Bearer";

            if (!string.IsNullOrWhiteSpace(token.DPoPJsonWebKey))
            {
                // looks like this is a DPoP bound token, so try to generate the proof token
                if (!await SetDPoPProofTokenAsync(request, token, cancellationToken))
                {
                    // failed or opted out for this request, to fall back to Bearer 
                    scheme = "Bearer";
                }
            }

            // checking for null AccessTokenType and falling back to "Bearer" since this might be coming
            // from an old cache/store prior to adding the AccessTokenType property.
            request.Headers.Authorization = new AuthenticationHeaderValue(scheme, token.AccessToken);
        }
    }

    /// <summary>
    /// Creates a DPoP proof token and attaches it to the request.
    /// </summary>
    protected virtual async Task<bool> SetDPoPProofTokenAsync(HttpRequestMessage request, ClientCredentialsToken token, CancellationToken cancellationToken, string? dpopNonce = null)
    {
        // remove any old headers
        request.Headers.Remove(OidcConstants.HttpHeaders.DPoP);

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
                // set new header
                request.Headers.Add(OidcConstants.HttpHeaders.DPoP, proofToken.ProofToken);
                return true;
            }
        }

        return false;
    }
}