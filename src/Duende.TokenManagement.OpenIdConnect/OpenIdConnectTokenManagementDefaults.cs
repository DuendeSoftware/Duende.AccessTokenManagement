namespace Duende.TokenManagement.OpenIdConnect;

/// <summary>
/// Default values
/// </summary>
public static class OpenIdConnectTokenManagementDefaults
{
    /// <summary>
    /// Prefix to use for registering client credentials client in options system on the fly
    /// </summary>
    public const string ClientCredentialsClientNamePrefix = "Duende.TokenManagement.OIDC.";
    
    /// <summary>
    /// Name of the back-channel HTTP client
    /// </summary>
    public const string BackChannelHttpClientName = "Duende.TokenManagement.OpenIdConnect.HttpClient";
}