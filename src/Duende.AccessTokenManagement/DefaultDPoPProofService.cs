// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using IdentityModel;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System;
using System.Threading.Tasks;
using System.Text;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.Extensions.Logging;

namespace Duende.AccessTokenManagement;

/// <summary>
/// Default implementation of IDPoPProofService
/// </summary>
public class DefaultDPoPProofService : IDPoPProofService
{
    private readonly IDPoPNonceStore _dPoPNonceStore;
    private readonly ILogger<DefaultDPoPProofService> _logger;

    /// <summary>
    /// ctor
    /// </summary>
    public DefaultDPoPProofService(IDPoPNonceStore dPoPNonceStore, ILogger<DefaultDPoPProofService> logger)
    {
        _dPoPNonceStore = dPoPNonceStore;
        _logger = logger;
    }

    /// <inheritdoc/>
    public virtual async Task<DPoPProof?> CreateProofTokenAsync(DPoPProofRequest request)
    {
        JsonWebKey jsonWebKey;
        
        try
        {
            jsonWebKey = new JsonWebKey(request.DPoPJsonWebKey);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to parse JSON web key.");
            return null;
        }

        // jwk: representing the public key chosen by the client, in JSON Web Key (JWK) [RFC7517] format,
        // as defined in Section 4.1.3 of [RFC7515]. MUST NOT contain a private key.
        Dictionary<string, string> jwk;
        if (string.Equals(jsonWebKey.Kty, JsonWebAlgorithmsKeyTypes.EllipticCurve))
        {
            jwk = new()
            {
                { "kty", jsonWebKey.Kty },
                { "x", jsonWebKey.X },
                { "y", jsonWebKey.Y },
                { "crv", jsonWebKey.Crv }
            };
        }
        else if (string.Equals(jsonWebKey.Kty, JsonWebAlgorithmsKeyTypes.RSA))
        {
            jwk = new()
            {
                { "kty", jsonWebKey.Kty },
                { "e", jsonWebKey.E },
                { "n", jsonWebKey.N }
            };
        }
        else
        {
            throw new InvalidOperationException("invalid key type.");
        }

        var header = new Dictionary<string, object>()
        {
            //{ "alg", "RS265" }, // JsonWebTokenHandler requires adding this itself
            { "typ", JwtClaimTypes.JwtTypes.DPoPProofToken },
            { JwtClaimTypes.JsonWebKey, jwk },
        };

        var payload = new Dictionary<string, object>
        {
            { JwtClaimTypes.JwtId, CryptoRandom.CreateUniqueId() },
            { JwtClaimTypes.DPoPHttpMethod, request.Method },
            { JwtClaimTypes.DPoPHttpUrl, request.Url },
            { JwtClaimTypes.IssuedAt, DateTimeOffset.UtcNow.ToUnixTimeSeconds() },
        };

        if (!string.IsNullOrWhiteSpace(request.AccessToken))
        {
            // ath: hash of the access token. The value MUST be the result of a base64url encoding 
            // the SHA-256 hash of the ASCII encoding of the associated access token's value.
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.ASCII.GetBytes(request.AccessToken));
            var ath = Base64Url.Encode(hash);

            payload.Add(JwtClaimTypes.DPoPAccessTokenHash, ath);
        }

        var nonce = request.DPoPNonce;
        if (string.IsNullOrEmpty(nonce))
        {
            nonce = await _dPoPNonceStore.GetNonceAsync(new DPoPNonceContext
            {
                Url = request.Url,
                Method = request.Method,
            });
        }
        else
        {
            await _dPoPNonceStore.StoreNonceAsync(new DPoPNonceContext
            {
                Url = request.Url,
                Method = request.Method,
            }, nonce);
        }

        if (!string.IsNullOrEmpty(nonce))
        {
            payload.Add(JwtClaimTypes.Nonce, nonce);
        }

        var handler = new JsonWebTokenHandler() { SetDefaultTimesOnTokenCreation = false };
        var key = new SigningCredentials(jsonWebKey, jsonWebKey.Alg);
        var proofToken = handler.CreateToken(JsonSerializer.Serialize(payload), key, header);

        return new DPoPProof { ProofToken = proofToken! };
    }

    /// <inheritdoc/>
    public virtual string? GetProofKeyThumbprint(DPoPProofRequest request)
    {
        try
        {
            var jsonWebKey = new JsonWebKey(request.DPoPJsonWebKey);
            return Base64UrlEncoder.Encode(jsonWebKey.ComputeJwkThumbprint());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to create thumbprint from JSON web key.");
        }
        return null;
    }
}
