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
    /// Reads the WWW-Authenticate response header to determine if the respone is in error due to DPoP
    /// </summary>
    public static bool IsDPoPError(this HttpResponseMessage response)
    {
        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
        {
            foreach (var header in response.Headers.WwwAuthenticate)
            {
                if (header.Scheme == OidcConstants.AuthenticationSchemes.AuthorizationHeaderDPoP
                    && header.Parameter is not null)
                {
                    // WWW-Authenticate: DPoP error="use_dpop_nonce"
                    var remaining = header.Parameter.AsSpan();

                    while (!remaining.IsEmpty)
                    {
                        ReadOnlySpan<char> parameter;

                        var separatorIndex = remaining.IndexOf(',');
                        if (separatorIndex == -1)
                        {
                            parameter = remaining;
                            remaining = ReadOnlySpan<char>.Empty;
                        }
                        else
                        {
                            parameter = remaining.Slice(0, separatorIndex);
                            remaining = remaining.Slice(separatorIndex + 1).Trim(' ');
                        }

                        if (!parameter.IsEmpty)
                        {
                            var equalsIndex = parameter.IndexOf("=");
                            if (equalsIndex != -1)
                            {
                                var name = parameter.Slice(0, equalsIndex).Trim(' ');
                                var value = parameter.Slice(equalsIndex + 1).Trim(' ').Trim('"');

                                if (name.SequenceEqual(OidcConstants.TokenResponse.Error.AsSpan()))
                                {
                                    return value.SequenceEqual(OidcConstants.TokenErrors.UseDPoPNonce.AsSpan())
                                        || value.SequenceEqual(OidcConstants.TokenErrors.InvalidDPoPProof.AsSpan());
                                }
                            }
                        }
                    }
                }
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