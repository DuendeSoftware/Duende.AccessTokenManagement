using System;
using Duende.TokenManagement.ClientCredentials;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

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
        string scheme = null;

        if (name.StartsWith(OpenIdConnectTokenManagementDefaults.ClientCredentialsClientNamePrefix))
        {
            if (name.Length > OpenIdConnectTokenManagementDefaults.ClientCredentialsClientNamePrefix.Length)
            {
                scheme = name[OpenIdConnectTokenManagementDefaults.ClientCredentialsClientNamePrefix.Length..];
            }
            
            // todo: how to async?
            var oidc = _configurationService.GetOpenIdConnectConfigurationAsync(scheme).GetAwaiter().GetResult();
            
            options.Address = oidc.TokenEndpoint;
            
            options.ClientId = oidc.ClientId;
            options.ClientSecret = oidc.ClientSecret;
            // todo: client credentials style
            
            options.Scope = _options.ClientCredentialsScope;
            options.Resource = _options.ClientCredentialsResource;
        }
    }
}