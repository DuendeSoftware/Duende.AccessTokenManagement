namespace Duende.TokenManagement.OpenIdConnect;

public class OpenIdConnectClientConfiguration
{
    public string TokenEndpoint { get; set; }
    public string RevocationEndpoint { get; set; }

    public string ClientId { get; set; }
    public string ClientSecret { get; set; }
}