using System.Threading.Tasks;

namespace Duende.AccessTokenManagement;

/// <summary>
/// Retrieves the token endpoint either using discovery or static configuration
/// </summary>
public interface ITokenEndpointRetriever
{
    /// <summary>
    /// Gets the token endpoint
    /// </summary>
    Task<string> GetAsync(ClientCredentialsClient client);
}
