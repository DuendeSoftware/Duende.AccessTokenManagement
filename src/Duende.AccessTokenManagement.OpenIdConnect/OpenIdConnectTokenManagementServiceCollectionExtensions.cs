// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Net.Http;
using Duende.AccessTokenManagement;
using Duende.AccessTokenManagement.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

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
        services.AddSingleton<IConfigureOptions<ClientCredentialsClient>, ConfigureOpenIdConnectClientCredentialsOptions>();
        // TODO: maybe return a builder with a ConfigureScheme that adds IConfigureNamedOptions/IPostConfigureNamedOptions with the naming convention?
        // for example, per-scheme client credentials style, scope, etc settings

        services.TryAddTransient<IUserTokenManagementService, UserAccessAccessTokenManagementService>();
        services.TryAddTransient<IOpenIdConnectConfigurationService, OpenIdConnectConfigurationService>();
        // scoped since it will be caching per-request authentication results
        services.TryAddScoped<IUserTokenStore, AuthenticationSessionUserAccessTokenStore>();
        services.TryAddSingleton<IUserTokenRequestSynchronization, UserTokenRequestSynchronization>();
        services.TryAddTransient<IUserTokenEndpointService, UserTokenEndpointService>();
        
        return services;
    }

    /// <summary>
    /// Adds the necessary services to manage user tokens based on OpenID Connect configuration
    /// </summary>
    /// <param name="services"></param>
    /// <param name="configureAction"></param>
    /// <returns></returns>
    public static IServiceCollection AddOpenIdConnectAccessTokenManagement(this IServiceCollection services,
        Action<UserTokenManagementOptions> configureAction)
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
        UserTokenRequestParameters? parameters = null,
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
        UserTokenRequestParameters? parameters = null,
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
        UserTokenRequestParameters? parameters = null,
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
        UserTokenRequestParameters? parameters = null)
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
        UserTokenRequestParameters? parameters = null)
    {
        return httpClientBuilder.AddHttpMessageHandler(provider =>
        {
            var contextAccessor = provider.GetRequiredService<IHttpContextAccessor>();

            return new OpenIdConnectClientAccessTokenHandler(contextAccessor, parameters);
        });
    }
}