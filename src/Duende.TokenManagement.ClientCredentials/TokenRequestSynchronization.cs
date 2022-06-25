using System.Collections.Concurrent;

namespace Duende.TokenManagement.ClientCredentials;

/// <summary>
/// Default implementation for token request synchronization primitive
/// </summary>
internal class TokenRequestSynchronization : ITokenRequestSynchronization
{
    /// <inheritdoc />
    public ConcurrentDictionary<string, Lazy<Task<AccessToken>>> Dictionary { get; } = new();
}