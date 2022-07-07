using System;
using System.Net.Http;
using Duende.TokenManagement.ClientCredentials;
using Duende.TokenManagement.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for IServiceCollection to register the user token management services
/// </summary>
public static class OpenIdConnectTokenManagementServiceCollectionExtensions
{
    /// <summary>
    /// Adds the necessary services to manage user tokens based on OpenID Connect configuration
    /// </summary>
    /// <param name="services"></param>
    /// <returns></returns>
    public static IServiceCollection AddOpenIdConnectAccessTokenManagement(this IServiceCollection services)
    {
        services.AddHttpContextAccessor();

        services.AddClientCredentialsTokenManagement();
        
        services.TryAddTransient<IUserService, DefaultUserService>();
        services.TryAddTransient<IUserTokenManagementService, UserAccessAccessTokenManagementService>();
        services.TryAddTransient<IUserTokenStore, AuthenticationSessionUserAccessTokenStore>();
        services.TryAddSingleton<IUserAccessTokenRequestSynchronization, UserAccessTokenRequestSynchronization>();
        services.TryAddTransient<IUserTokenConfigurationService, DefaultUserTokenConfigurationService>();
        services.TryAddTransient<IUserTokenEndpointService, UserAccessTokenEndpointService>();

        return services;
    }

    /// <summary>
    /// Adds the necessary services to manage user tokens based on OpenID Connect configuration
    /// </summary>
    /// <param name="services"></param>
    /// <param name="configureAction"></param>
    /// <returns></returns>
    public static IServiceCollection AddOpenIdConnectAccessTokenManagement(this IServiceCollection services,
        Action<UserAccessTokenManagementOptions> configureAction)
    {
        services.Configure(configureAction);

        return services.AddOpenIdConnectAccessTokenManagement();
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
        ClientCredentialsTokenRequestParameters? parameters = null,
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
        return httpClientBuilder.AddHttpMessageHandler<OpenIdConnectUserAccessTokenHandler>();
        return httpClientBuilder.AddHttpMessageHandler(provider =>
        {
            var userService = provider.GetRequiredService<IUserService>();
            var managementService = provider.GetRequiredService<IUserTokenManagementService>();

            return new OpenIdConnectUserAccessTokenHandler(managementService, userService, parameters);
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
        ClientCredentialsTokenRequestParameters? parameters = null)
    {
        return httpClientBuilder.AddHttpMessageHandler(provider =>
        {
            var contextAccessor = provider.GetRequiredService<IHttpContextAccessor>();

            return new OpenIdConnectClientAccessTokenHandler(contextAccessor, parameters);
        });
    }
}