using Duende.AccessTokenManagement;
using IdentityModel.Client;

namespace ClientCredentialTests.Services;

public class TestClientAssertionService : IClientAssertionService
{
    private readonly string _clientName;
    private readonly string _assertionType;
    private readonly string _assertionValue;

    public TestClientAssertionService(string clientName, string assertionType, string assertionValue)
    {
        _clientName = clientName;
        _assertionType = assertionType;
        _assertionValue = assertionValue;
    }
    
    public Task<ClientAssertion?> GetClientAssertionAsync(string clientName, ClientCredentialsTokenRequestParameters? parameters = null)
    {
        if (clientName == _clientName)
        {
            return Task.FromResult<ClientAssertion?>(new()
            {
                Type = _assertionType,
                Value = _assertionValue
            });
        }

        return Task.FromResult<ClientAssertion?>(null);
    }
}