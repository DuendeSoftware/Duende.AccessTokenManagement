// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Net.Http;
using Duende.AccessTokenManagement;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for IServiceCollection to register the client credentials token management services
/// </summary>
public static class ClientCredentialsTokenManagementServiceCollectionExtensions
{
    /// <summary>
    /// Adds all necessary services for client credentials token management
    /// </summary>
    /// <param name="services"></param>
    /// <param name="options"></param>
    /// <returns></returns>
    public static ClientCredentialsTokenManagementBuilder AddClientCredentialsTokenManagement(
        this IServiceCollection services, 
        Action<ClientCredentialsTokenManagementOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        services.Configure(options);
        return services.AddClientCredentialsTokenManagement();
    }

    /// <summary>
    /// Adds all necessary services for client credentials token management
    /// </summary>
    /// <param name="services"></param>
    /// <returns></returns>
    public static ClientCredentialsTokenManagementBuilder AddClientCredentialsTokenManagement(this IServiceCollection services)
    {
        services.TryAddSingleton<ITokenRequestSynchronization, TokenRequestSynchronization>();
        
        services.TryAddTransient<IClientCredentialsTokenManagementService, ClientCredentialsTokenManagementService>();
        services.TryAddTransient<IClientCredentialsTokenCache, DistributedClientCredentialsTokenCache>();
        services.TryAddTransient<IClientCredentialsTokenEndpointService, ClientCredentialsTokenEndpointService>();
        services.TryAddTransient<IClientAssertionService, DefaultClientAssertionService>();
        
        services.AddHttpClient(ClientCredentialsTokenManagementDefaults.BackChannelHttpClientName);

        return new ClientCredentialsTokenManagementBuilder(services);
    }
    
    /// <summary>
    /// Adds a named HTTP client for the factory that automatically sends the a client access token
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/>.</param>
    /// <param name="httpClientName">The name of the client.</param>
    /// <param name="tokenClientName">The name of the token client.</param>
    /// <param name="configureClient">A delegate that is used to configure a <see cref="HttpClient"/>.</param>
    /// <returns></returns>
    public static IHttpClientBuilder AddClientCredentialsHttpClient(
        this IServiceCollection services, 
        string httpClientName,
        string tokenClientName,
        Action<HttpClient>? configureClient = null)
    {
        ArgumentNullException.ThrowIfNull(httpClientName);
        ArgumentNullException.ThrowIfNull(tokenClientName);
        
        if (configureClient != null)
        {
            return services.AddHttpClient(httpClientName, configureClient)
                .AddClientCredentialsTokenHandler(tokenClientName);
        }

        return services.AddHttpClient(httpClientName)
            .AddClientCredentialsTokenHandler(tokenClientName);
    }
        
    /// <summary>
    /// Adds a named HTTP client for the factory that automatically sends the a client access token
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/>.</param>
    /// <param name="httpClientName">The name of the client.</param>
    /// <param name="tokenClientName">The name of the token client.</param>
    /// <param name="configureClient">Additional configuration with service provider instance.</param>
    /// <returns></returns>
    public static IHttpClientBuilder AddClientCredentialsHttpClient(
        this IServiceCollection services,
        string httpClientName,
        string tokenClientName,
        Action<IServiceProvider, HttpClient>? configureClient = null)
    {
        ArgumentNullException.ThrowIfNull(httpClientName);
        ArgumentNullException.ThrowIfNull(tokenClientName);
        
        if (configureClient != null)
        {
            return services.AddHttpClient(httpClientName, configureClient)
                .AddClientCredentialsTokenHandler(tokenClientName);
        }

        return services.AddHttpClient(httpClientName)
            .AddClientCredentialsTokenHandler(tokenClientName);
    }
    
    /// <summary>
    /// Adds the client access token handler to an HttpClient
    /// </summary>
    /// <param name="httpClientBuilder"></param>
    /// <param name="tokenClientName"></param>
    /// <returns></returns>
    public static IHttpClientBuilder AddClientCredentialsTokenHandler(
        this IHttpClientBuilder httpClientBuilder,
        string tokenClientName)
    {
        ArgumentNullException.ThrowIfNull(tokenClientName);
        
        return httpClientBuilder.AddHttpMessageHandler(provider =>
        {
            var accessTokenManagementService = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

            return new ClientCredentialsTokenHandler(accessTokenManagementService, tokenClientName);
        });
    }
}