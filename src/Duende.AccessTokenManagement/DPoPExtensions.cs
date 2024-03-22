// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Linq;
using System.Net.Http;
using IdentityModel;

namespace Duende.AccessTokenManagement;

/// <summary>
/// Extensions for HTTP request/response messages
/// </summary>
public static class DPoPExtensions
{
    /// <summary>
    /// Clears any existing DPoP nonce headers.
    /// </summary>
    public static void ClearDPoPProofToken(this HttpRequestMessage request)
    {
        // remove any old headers
        request.Headers.Remove(OidcConstants.HttpHeaders.DPoP);
    }

    /// <summary>
    /// Sets the DPoP nonce request header if nonce is not null. 
    /// </summary>
    public static void SetDPoPProofToken(this HttpRequestMessage request, string? proofToken)
    {
        // set new header
        request.Headers.Add(OidcConstants.HttpHeaders.DPoP, proofToken);
    }

    /// <summary>
    /// Reads the DPoP nonce header from the response
    /// </summary>
    public static string? GetDPoPNonce(this HttpResponseMessage response)
    {
        var nonce = response.Headers
            .FirstOrDefault(x => x.Key == OidcConstants.HttpHeaders.DPoPNonce)
            .Value?.FirstOrDefault();
        return nonce;
    }

    /// <summary>
    /// Reads the WWW-Authenticate response header to determine if the response is in error due to DPoP
    /// </summary>
    public static bool IsDPoPError(this HttpResponseMessage response)
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
                        return parts[1].Trim('"');
                    }
                    return null;
                }).Where(x => x != null).FirstOrDefault();

                return error == OidcConstants.TokenErrors.UseDPoPNonce || error == OidcConstants.TokenErrors.InvalidDPoPProof;
            }
        }

        return false;
    }

    /// <summary>
    /// Returns the URL without any query params
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    public static string GetDPoPUrl(this HttpRequestMessage request)
    {
        return request.RequestUri!.Scheme + "://" + request.RequestUri!.Authority + request.RequestUri!.LocalPath;
    }
}