using System.Threading.Tasks;
using IdentityModel.Client;

namespace Duende.TokenManagement.ClientCredentials;

/// <inheritdoc />
public class DefaultClientAssertionService : IClientAssertionService
{
    /// <inheritdoc />
    public Task<ClientAssertion?> GetClientAssertionAsync(string clientName, ClientCredentialsTokenRequestParameters? parameters = null)
    {
        return Task.FromResult<ClientAssertion?>(null);
    }
}