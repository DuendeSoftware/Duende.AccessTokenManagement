// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Threading.Tasks;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <inheritdoc />
public class OpenIdConnectConfigurationService : IOpenIdConnectConfigurationService
{
    private readonly IOptions<UserTokenManagementOptions> _userAccessTokenManagementOptions;
    private readonly IOptionsMonitor<OpenIdConnectOptions> _oidcOptionsMonitor;
    private readonly IAuthenticationSchemeProvider _schemeProvider;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="userAccessTokenManagementOptions"></param>
    /// <param name="oidcOptionsMonitor"></param>
    /// <param name="schemeProvider"></param>
    public OpenIdConnectConfigurationService(
        IOptions<UserTokenManagementOptions> userAccessTokenManagementOptions,
        IOptionsMonitor<OpenIdConnectOptions> oidcOptionsMonitor,
        IAuthenticationSchemeProvider schemeProvider)
    {
        _userAccessTokenManagementOptions = userAccessTokenManagementOptions;
        _oidcOptionsMonitor = oidcOptionsMonitor;
        _schemeProvider = schemeProvider;
    }

    /// <inheritdoc />
    public async Task<OpenIdConnectClientConfiguration> GetOpenIdConnectConfigurationAsync(string? schemeName = null)
    {
        OpenIdConnectOptions options;

        var configScheme = schemeName ?? _userAccessTokenManagementOptions.Value.ChallengeScheme;

        if (string.IsNullOrWhiteSpace(configScheme))
        {
            var defaultScheme = await _schemeProvider.GetDefaultChallengeSchemeAsync();

            if (defaultScheme is null)
            {
                throw new InvalidOperationException(
                    "No OpenID Connect authentication scheme configured for getting client configuration. Either set the scheme name explicitly or set the default challenge scheme");
            }

            configScheme = defaultScheme.Name;
        }

        options = _oidcOptionsMonitor.Get(configScheme);

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

        return new OpenIdConnectClientConfiguration
        {
            Scheme = configScheme,
            
            Authority = options.Authority,
            TokenEndpoint = configuration.TokenEndpoint,
            RevocationEndpoint = configuration.AdditionalData.TryGetValue(OidcConstants.Discovery.RevocationEndpoint, out var value) ? value?.ToString() : null,
            
            ClientId = options.ClientId,
            ClientSecret = options.ClientSecret,
            HttpClient = options.Backchannel,
        };
    }
}