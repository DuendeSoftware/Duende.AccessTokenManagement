using Duende.TokenManagement.ClientCredentials;
using Microsoft.Extensions.Options;

namespace Duende.TokenManagement.OpenIdConnect;

public class ConfigureOpenIdConnectClientCredentialsOptions : IConfigureNamedOptions<ClientCredentialsClient>
{
    private readonly IOpenIdConnectConfigurationService _configurationService;
    private readonly UserAccessTokenManagementOptions _options;

    public ConfigureOpenIdConnectClientCredentialsOptions(
        IOpenIdConnectConfigurationService configurationService,
        IOptions<UserAccessTokenManagementOptions> options)
    {
        _configurationService = configurationService;
        _options = options.Value;
    }
    
    public void Configure(ClientCredentialsClient options)
    { }

    public void Configure(string name, ClientCredentialsClient options)
    {
        if (name.Equals(OpenIdConnectTokenManagementDefaults.ClientCredentialsClientNamePrefix))
        {
            // todo: how to async?
            var oidc = _configurationService.GetOpenIdConnectConfigurationAsync().GetAwaiter().GetResult();

            options.Address = oidc.configuration.TokenEndpoint;
            options.ClientId = oidc.options.ClientId;
            options.ClientSecret = oidc.options.ClientSecret;
            options.Scope = _options.ClientCredentialsScope;
            options.Resource = _options.ClientCredentialsResource;
        }
        
        // todo: add support for explicit schemes
    }
}