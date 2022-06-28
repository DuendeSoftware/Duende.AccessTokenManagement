using System;
using Duende.TokenManagement.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

public static class OpenIdConnectTokenManagementServiceCollectionExtensions
{
    public static IServiceCollection AddOpenIdConnectTokenManagement(this IServiceCollection services)
    {
        services.AddClientCredentialsTokenManagement();
        
        services.TryAddSingleton<ISystemClock, SystemClock>();
        services.TryAddSingleton<IAuthenticationSchemeProvider, AuthenticationSchemeProvider>();
        services.AddHttpContextAccessor();
        
        services.TryAddTransient<IUserTokenManagementService, UserAccessAccessTokenManagementService>();
        services.TryAddTransient<IUserTokenStore, AuthenticationSessionUserAccessTokenStore>();
        services.TryAddSingleton<ITokenRequestSynchronization, TokenRequestSynchronization>();
        services.TryAddTransient<IUserTokenConfigurationService, DefaultUserTokenConfigurationService>();
        services.TryAddTransient<IUserTokenEndpointService, UserTokenEndpointService>();

        return services;
    }

    public static IServiceCollection AddOpenIdConnectTokenManagement(this IServiceCollection services,
        Action<UserAccessTokenManagementOptions> configureAction)
    {
        services.Configure(configureAction);

        return services.AddOpenIdConnectTokenManagement();
    }
}