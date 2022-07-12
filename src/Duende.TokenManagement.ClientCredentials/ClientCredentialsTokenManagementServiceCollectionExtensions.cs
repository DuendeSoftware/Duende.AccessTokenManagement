// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Net.Http;
using Duende.TokenManagement.ClientCredentials;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection;

public class ClientCredentialsTokenManagementBuilder
{
    private readonly IServiceCollection _services;

    public ClientCredentialsTokenManagementBuilder(IServiceCollection services)
    {
        _services = services;
    }

    public ClientCredentialsTokenManagementBuilder AddClient(string name, Action<ClientCredentialsClientOptions> configureOptions)
    {
        _services.Configure(name, configureOptions);
        return this;
    }
}

/// <summary>
/// Extension methods for IServiceCollection to register the client credentials token management services
/// </summary>
public static class ClientCredentialsTokenManagementServiceCollectionExtensions
{
    /// <summary>
    /// Adds all necessary services for client credentials token management
    /// </summary>
    /// <param name="services"></param>
    /// <returns></returns>
    public static ClientCredentialsTokenManagementBuilder AddClientCredentialsTokenManagement(this IServiceCollection services)
    {
        services.TryAddTransient<IClientCredentialsTokenManagementService, ClientCredentialsTokenManagementService>();
        services.TryAddTransient<IClientCredentialsTokenCache, DistributedClientCredentialsTokenCache>();
        services.TryAddTransient<IClientCredentialsConfigurationService, DefaultClientCredentialsConfigurationService>();
        services.TryAddTransient<IClientCredentialsTokenEndpointService, ClientCredentialsTokenEndpointService>();
        services.TryAddSingleton<ITokenRequestSynchronization, TokenRequestSynchronization>();

        services.AddHttpClient(TokenManagementDefaults.BackChannelHttpClientName);

        return new ClientCredentialsTokenManagementBuilder(services);
    }
        
    /// <summary>
    /// Adds all necessary services for client credentials token management. Also allows configuring clients.
    /// </summary>
    /// <param name="services"></param>
    /// <param name="configureAction"></param>
    /// <returns></returns>
    // public static IServiceCollection AddClientCredentialsTokenManagement(this IServiceCollection services,
    //     Action<ClientCredentialsTokenManagementOptions> configureAction)
    // {
    //     services.Configure(configureAction);
    //
    //     return services.AddClientCredentialsTokenManagement();
    // }
    
    /// <summary>
    /// Adds a named HTTP client for the factory that automatically sends the a client access token
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/>.</param>
    /// <param name="clientName">The name of the client.</param>
    /// <param name="tokenClientName">The name of the token client.</param>
    /// <param name="configureClient">A delegate that is used to configure a <see cref="HttpClient"/>.</param>
    /// <returns></returns>
    public static IHttpClientBuilder AddClientCredentialsHttpClient(
        this IServiceCollection services, 
        string clientName,
        string tokenClientName = TokenManagementDefaults.DefaultTokenClientName,
        Action<HttpClient>? configureClient = null)
    {
        if (configureClient != null)
        {
            return services.AddHttpClient(clientName, configureClient)
                .AddClientCredentialsTokenHandler(tokenClientName);
        }

        return services.AddHttpClient(clientName)
            .AddClientCredentialsTokenHandler(tokenClientName);
    }
        
    /// <summary>
    /// Adds a named HTTP client for the factory that automatically sends the a client access token
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/>.</param>
    /// <param name="clientName">The name of the client.</param>
    /// <param name="tokenClientName">The name of the token client.</param>
    /// <param name="configureClient">Additional configuration with service provider instance.</param>
    /// <returns></returns>
    public static IHttpClientBuilder AddClientCredentialsHttpClient(
        this IServiceCollection services,
        string clientName,
        string tokenClientName = TokenManagementDefaults.DefaultTokenClientName,
        Action<IServiceProvider, HttpClient>? configureClient = null)
    {
        if (configureClient != null)
        {
            return services.AddHttpClient(clientName, configureClient)
                .AddClientCredentialsTokenHandler(tokenClientName);
        }

        return services.AddHttpClient(clientName)
            .AddClientCredentialsTokenHandler(tokenClientName);
    }

    //
    /// <summary>
    /// Adds the client access token handler to an HttpClient
    /// </summary>
    /// <param name="httpClientBuilder"></param>
    /// <param name="tokenClientName"></param>
    /// <returns></returns>
    public static IHttpClientBuilder AddClientCredentialsTokenHandler(
        this IHttpClientBuilder httpClientBuilder,
        string tokenClientName = TokenManagementDefaults.DefaultTokenClientName)
    {
        return httpClientBuilder.AddHttpMessageHandler(provider =>
        {
            var accessTokenManagementService = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

            return new ClientCredentialsTokenHandler(accessTokenManagementService, tokenClientName);
        });
    }
}