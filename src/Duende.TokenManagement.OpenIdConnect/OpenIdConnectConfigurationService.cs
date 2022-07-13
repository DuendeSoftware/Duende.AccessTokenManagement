using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Duende.TokenManagement.OpenIdConnect;

/// <inheritdoc />
public class OpenIdConnectConfigurationService : IOpenIdConnectConfigurationService
{
    private readonly IOptions<UserAccessTokenManagementOptions> _userAccessTokenManagementOptions;
    private readonly IOptionsMonitor<OpenIdConnectOptions> _oidcOptionsMonitor;
    private readonly IAuthenticationSchemeProvider _schemeProvider;

    public OpenIdConnectConfigurationService(
        IOptions<UserAccessTokenManagementOptions> userAccessTokenManagementOptions,
        IOptionsMonitor<OpenIdConnectOptions> oidcOptionsMonitor,
        IAuthenticationSchemeProvider schemeProvider)
    {
        _userAccessTokenManagementOptions = userAccessTokenManagementOptions;
        _oidcOptionsMonitor = oidcOptionsMonitor;
        _schemeProvider = schemeProvider;
    }
    
    public async Task<(OpenIdConnectOptions options, OpenIdConnectConfiguration configuration)> GetOpenIdConnectConfigurationAsync(string? schemeName = null)
    {
        OpenIdConnectOptions options;

        var configScheme = schemeName ?? _userAccessTokenManagementOptions.Value.SchemeName;

        if (string.IsNullOrWhiteSpace(configScheme))
        {
            var scheme = await _schemeProvider.GetDefaultChallengeSchemeAsync();

            if (scheme is null)
            {
                throw new InvalidOperationException(
                    "No OpenID Connect authentication scheme configured for getting client configuration. Either set the scheme name explicitly or set the default challenge scheme");
            }

            options = _oidcOptionsMonitor.Get(scheme.Name);
        }
        else
        {
            options = _oidcOptionsMonitor.Get(configScheme);
        }

        OpenIdConnectConfiguration configuration;
        try
        {
            configuration = await options.ConfigurationManager!.GetConfigurationAsync(default);
        }
        catch (Exception e)
        {
            throw new InvalidOperationException(
                $"Unable to load OpenID configuration for configured scheme: {e.Message}");
        }

        return (options, configuration);
    }
}