using System.Collections.Concurrent;

namespace Duende.TokenManagement.ClientCredentials;

/// <summary>
/// Service to provide a concurrent dictionary for synchronizing token endpoint requests
/// </summary>
public interface ITokenRequestSynchronization
{
    /// <summary>
    /// Concurrent dictionary as synchronization primitive
    /// </summary>
    public ConcurrentDictionary<string, Lazy<Task<AccessToken>>> Dictionary { get; }
}