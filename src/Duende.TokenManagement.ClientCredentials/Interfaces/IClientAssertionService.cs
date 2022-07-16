using System.Threading.Tasks;
using IdentityModel.Client;

namespace Duende.TokenManagement.ClientCredentials;

/// <summary>
/// Service to create client assertions for back-channel clients
/// </summary>
public interface IClientAssertionService
{
    /// <summary>
    /// Creates a client assertion based on client or configuration scheme (if present)
    /// </summary>
    /// <param name="clientName"></param>
    /// <param name="parameters"></param>
    /// <returns></returns>
    Task<ClientAssertion?> GetClientAssertionAsync(string clientName, ClientCredentialsTokenRequestParameters? parameters = null);
}