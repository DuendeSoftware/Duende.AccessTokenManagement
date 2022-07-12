using IdentityModel.Client;

namespace Duende.TokenManagement.ClientCredentials;

public class ClientCredentialsClient
{
    public string Address { get; set; }
    public string ClientId { get; set; }
    public string ClientSecret { get; set; }

    public ClientCredentialStyle ClientCredentialStyle { get; set; }

    public string Scope { get; set; }
    public string Resource { get; set; }

    public string HttpClientName { get; set; }
}