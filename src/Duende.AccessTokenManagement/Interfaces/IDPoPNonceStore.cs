// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Threading;
using System.Threading.Tasks;

namespace Duende.AccessTokenManagement;

/// <summary>
/// Service to keep track of DPoP nonces
/// </summary>
public interface IDPoPNonceStore
{
    /// <summary>
    /// Gets the nonce 
    /// </summary>
    Task<string?> GetNonceAsync(DPoPNonceContext context, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Stores the nonce 
    /// </summary>
    Task StoreNonceAsync(DPoPNonceContext context, string nonce, CancellationToken cancellationToken = default);
}

/// <summary>
/// The context for a DPoP nonce.
/// </summary>
public class DPoPNonceContext
{
    /// <summary>
    /// The HTTP URL of the request
    /// </summary>
    public string Url { get; set; } = default!;

    /// <summary>
    /// The HTTP method of the request
    /// </summary>
    public string Method { get; set; } = default!;
}