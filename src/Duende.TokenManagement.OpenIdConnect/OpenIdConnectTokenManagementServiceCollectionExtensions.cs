using System;
using System.Net.Http;
using Duende.TokenManagement.ClientCredentials;
using Duende.TokenManagement.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection.Extensions;
using ITokenRequestSynchronization = Duende.TokenManagement.OpenIdConnect.ITokenRequestSynchronization;

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
        services.TryAddTransient<IUserTokenEndpointService, UserAccessTokenEndpointService>();

        return services;
    }

    public static IServiceCollection AddOpenIdConnectTokenManagement(this IServiceCollection services,
        Action<UserAccessTokenManagementOptions> configureAction)
    {
        services.Configure(configureAction);

        return services.AddOpenIdConnectTokenManagement();
    }
    
    /// <summary>
    /// Adds a named HTTP client for the factory that automatically sends the current user access token
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/>.</param>
    /// <param name="name">The name of the client.</param>
    /// <param name="parameters"></param>
    /// <param name="configureClient">Additional configuration with service provider instance.</param>
    /// <returns></returns>
    public static IHttpClientBuilder AddUserAccessTokenHttpClient(this IServiceCollection services,
        string name,
        UserAccessTokenRequestParameters? parameters = null,
        Action<IServiceProvider, HttpClient>? configureClient = null)
    {
        if (configureClient != null)
        {
            return services.AddHttpClient(name, configureClient)
                .AddUserAccessTokenHandler(parameters);
        }

        return services.AddHttpClient(name)
            .AddUserAccessTokenHandler(parameters);
    }
    
    /// <summary>
    /// Adds a named HTTP client for the factory that automatically sends the current user access token
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/>.</param>
    /// <param name="name">The name of the client.</param>
    /// <param name="parameters"></param>
    /// <param name="configureClient">Additional configuration with service provider instance.</param>
    /// <returns></returns>
    public static IHttpClientBuilder AddUserAccessTokenHttpClient(this IServiceCollection services,
        string name,
        UserAccessTokenRequestParameters? parameters = null,
        Action<HttpClient>? configureClient = null)
    {
        if (configureClient != null)
        {
            return services.AddHttpClient(name, configureClient)
                .AddUserAccessTokenHandler(parameters);
        }

        return services.AddHttpClient(name)
            .AddUserAccessTokenHandler(parameters);
    }
    
    /// <summary>
    /// Adds a named HTTP client for the factory that automatically sends the current user access token
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/>.</param>
    /// <param name="name">The name of the client.</param>
    /// <param name="parameters"></param>
    /// <param name="configureClient">Additional configuration with service provider instance.</param>
    /// <returns></returns>
    public static IHttpClientBuilder AddClientAccessTokenHttpClient(this IServiceCollection services,
        string name,
        AccessTokenRequestParameters? parameters = null,
        Action<HttpClient>? configureClient = null)
    {
        if (configureClient != null)
        {
            return services.AddHttpClient(name, configureClient)
                .AddClientAccessTokenHandler(parameters);
        }

        return services.AddHttpClient(name)
            .AddClientAccessTokenHandler(parameters);
    }

    
    /// <summary>
    /// Adds the user access token handler to an HttpClient
    /// </summary>
    /// <param name="httpClientBuilder"></param>
    /// <param name="parameters"></param>
    /// <returns></returns>
    public static IHttpClientBuilder AddUserAccessTokenHandler(
        this IHttpClientBuilder httpClientBuilder,
        UserAccessTokenRequestParameters? parameters = null)
    {
        return httpClientBuilder.AddHttpMessageHandler(provider =>
        {
            var contextAccessor = provider.GetRequiredService<IHttpContextAccessor>();

            return new OpenIdConnectUserAccessTokenHandler(contextAccessor, parameters);
        });
    }
    
    /// <summary>
    /// Adds the user access token handler to an HttpClient
    /// </summary>
    /// <param name="httpClientBuilder"></param>
    /// <param name="parameters"></param>
    /// <returns></returns>
    public static IHttpClientBuilder AddClientAccessTokenHandler(
        this IHttpClientBuilder httpClientBuilder,
        AccessTokenRequestParameters? parameters = null)
    {
        return httpClientBuilder.AddHttpMessageHandler(provider =>
        {
            var contextAccessor = provider.GetRequiredService<IHttpContextAccessor>();

            return new OpenIdConnectClientAccessTokenHandler(contextAccessor, parameters);
        });
    }
}