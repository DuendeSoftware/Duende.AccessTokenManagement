using System;
using System.Threading.Tasks;
using Duende.TokenManagement.ClientCredentials;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Duende.TokenManagement.OpenIdConnect;

/// <summary>
/// Options-based configuration service for token clients
/// </summary>
public class DefaultUserTokenConfigurationService : IUserTokenConfigurationService
{
    private readonly UserAccessTokenManagementOptions _userAccessTokenManagementOptions;
    private readonly IOptionsMonitor<OpenIdConnectOptions> _oidcOptionsMonitor;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly ILogger<DefaultUserTokenConfigurationService> _logger;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="userAccessTokenManagementOptions"></param>
    /// <param name="oidcOptionsMonitor"></param>
    /// <param name="schemeProvider"></param>
    /// <param name="logger"></param>
    public DefaultUserTokenConfigurationService(
        IOptions<UserAccessTokenManagementOptions> userAccessTokenManagementOptions,
        IOptionsMonitor<OpenIdConnectOptions> oidcOptionsMonitor,
        IAuthenticationSchemeProvider schemeProvider,
        ILogger<DefaultUserTokenConfigurationService> logger)
    {
        _userAccessTokenManagementOptions = userAccessTokenManagementOptions.Value;
        _oidcOptionsMonitor = oidcOptionsMonitor;
        _schemeProvider = schemeProvider;
        _logger = logger;
    }

    /// <inheritdoc />
    public virtual async Task<RefreshTokenRequest> GetRefreshTokenRequestAsync(
        UserAccessTokenRequestParameters parameters)
    {
        var (options, configuration) =
            await GetOpenIdConnectSettingsAsync(parameters.ChallengeScheme ??
                                                _userAccessTokenManagementOptions.SchemeName);

        var request = new RefreshTokenRequest
        {
            Address = configuration.TokenEndpoint,
            ClientCredentialStyle = _userAccessTokenManagementOptions.ClientCredentialStyle,

            ClientId = options.ClientId,
            ClientSecret = options.ClientSecret
        };

        if (!string.IsNullOrEmpty(parameters.Resource))
        {
            request.Resource.Add(parameters.Resource);
        }

        await ApplyAssertionAsync(request, parameters);
        return request;
    }

    /// <inheritdoc />
    public virtual async Task<TokenRevocationRequest> GetTokenRevocationRequestAsync(
        UserAccessTokenRequestParameters parameters)
    {
        var (options, configuration) =
            await GetOpenIdConnectSettingsAsync(parameters.ChallengeScheme ??
                                                _userAccessTokenManagementOptions.SchemeName);

        var request = new TokenRevocationRequest
        {
            Address = configuration.AdditionalData[OidcConstants.Discovery.RevocationEndpoint].ToString(),
            ClientCredentialStyle = _userAccessTokenManagementOptions.ClientCredentialStyle,

            ClientId = options.ClientId,
            ClientSecret = options.ClientSecret,
        };

        await ApplyAssertionAsync(request, parameters);
        return request;
    }

    // todo: need to apply per request parameters here!
    public virtual async Task<ClientCredentialsTokenRequest> GetClientCredentialsRequestAsync(AccessTokenRequestParameters parameters)
    {
        var (options, configuration) =
            await GetOpenIdConnectSettingsAsync(_userAccessTokenManagementOptions.SchemeName);

        var request = new ClientCredentialsTokenRequest
        {
            Address = configuration.TokenEndpoint,
            ClientCredentialStyle = _userAccessTokenManagementOptions.ClientCredentialStyle,

            ClientId = options.ClientId,
            ClientSecret = options.ClientSecret,
        };

        if (parameters.Scope.IsPresent())
        {
            request.Scope = parameters.Scope;
        }
        else if (_userAccessTokenManagementOptions.ClientCredentialsScope.IsPresent())
        {
            request.Scope = _userAccessTokenManagementOptions.ClientCredentialsScope;
        }
        
        if (parameters.Resource.IsPresent())
        {
            request.Resource.Add(parameters.Resource);
        }
        else if (_userAccessTokenManagementOptions.ClientCredentialsResource.IsPresent())
        {
            request.Resource.Add(_userAccessTokenManagementOptions.ClientCredentialsResource);
        }

        await ApplyAssertionAsync(request, parameters);
        return request;
    }

    /// <summary>
    /// Retrieves configuration from a named OpenID Connect handler
    /// </summary>
    /// <param name="schemeName"></param>
    /// <returns></returns>
    /// <exception cref="InvalidOperationException"></exception>
    public virtual async Task<(OpenIdConnectOptions options, OpenIdConnectConfiguration configuration)>
        GetOpenIdConnectSettingsAsync(string? schemeName)
    {
        OpenIdConnectOptions options;

        if (string.IsNullOrWhiteSpace(schemeName))
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
            options = _oidcOptionsMonitor.Get(schemeName);
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

    async Task ApplyAssertionAsync(ProtocolRequest request, AccessTokenRequestParameters parameters)
    {
        if (parameters.Assertion != null)
        {
            request.ClientAssertion = parameters.Assertion;
        }
        else
        {
            var assertion = await CreateAssertionAsync();
            if (assertion != null)
            {
                request.ClientCredentialStyle = ClientCredentialStyle.PostBody;
                request.ClientAssertion = assertion;
            }    
        }
    }

    /// <summary>
    /// Allows injecting a client assertion into outgoing requests
    /// </summary>
    /// <param name="clientName">Name of client (if present)</param>
    /// <returns></returns>
    protected virtual Task<ClientAssertion?> CreateAssertionAsync(string? clientName = null)
    {
        return Task.FromResult<ClientAssertion?>(null);
    }
}