// Copyright (c) Duende Software. All rights reserved.
// See LICENSE in the project root for license information.


namespace Duende.AccessTokenManagement.Tests;

public class TestDPoPProofService : IDPoPProofService
{
    public string? ProofToken { get; set; }
    public string? Nonce { get; set; }
    public bool AppendNonce { get; set; }

    public Task<DPoPProof?> CreateProofTokenAsync(DPoPProofRequest request)
    {
        if (ProofToken == null) return Task.FromResult<DPoPProof?>(null);
        Nonce = request.DPoPNonce;
        return Task.FromResult<DPoPProof?>(new DPoPProof { ProofToken = ProofToken + Nonce });
    }

    public string? GetProofKeyThumbprint(DPoPProofRequest request)
    {
        return null;
    }
}