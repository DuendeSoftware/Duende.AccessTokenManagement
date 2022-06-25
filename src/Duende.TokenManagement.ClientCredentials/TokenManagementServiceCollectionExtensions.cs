// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Duende.TokenManagement.ClientCredentials;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Internal;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Extension methods for IServiceCollection to register the client credentials token management services
    /// </summary>
    public static class TokenManagementServiceCollectionExtensions
    {
        public static IServiceCollection AddClientCredentialsTokenManagement(this IServiceCollection services,
            Action<ClientCredentialsTokenManagementOptions> configureAction)
        {
            services.Configure(configureAction);


            //services.AddDistributedMemoryCache();
            services.TryAddSingleton<ISystemClock, SystemClock>();

            services.TryAddTransient<IClientCredentialsTokenManagementService, ClientCredentialsTokenManagementService>();
            services.TryAddTransient<IAccessTokenCache, DistributedAccessTokenCache>();
            services.TryAddSingleton<ITokenRequestSynchronization, TokenRequestSynchronization>();
            services.TryAddTransient<ITokenClientConfigurationService, DefaultTokenClientConfigurationService>();
            services.TryAddTransient<IClientCredentialsTokenEndpointService, ClientCredentialsTokenEndpointService>();

            services.AddHttpClient(TokenManagementDefaults.BackChannelHttpClientName);

            return services;
        }


        // /// <summary>
        // /// Adds the services required for client access token management using all default values
        // /// </summary>
        // /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        // /// <returns></returns>
        // public static TokenManagementBuilder AddClientAccessTokenManagement(this IServiceCollection services)
        // {
        //     CheckConfigMarker(services);
        //     
        //     var clientOptions = new ClientAccessTokenManagementOptions();
        //     
        //     services.AddSingleton(clientOptions);
        //     services.AddSingleton(new UserAccessTokenManagementOptions());
        //
        //     return services.AddClientAccessTokenManagementInternal();
        // }
        //
        // /// <summary>
        // /// Adds the services required for client access token management
        // /// </summary>
        // /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        // /// <param name="configureAction">A delegate that is used to configure a <see cref="ClientAccessTokenManagementOptions"/>.</param>
        // /// <returns></returns>
        // public static TokenManagementBuilder AddClientAccessTokenManagement(
        //     this IServiceCollection services,
        //     Action<ClientAccessTokenManagementOptions> configureAction)
        // {
        //     CheckConfigMarker(services);
        //     
        //     var clientOptions = new ClientAccessTokenManagementOptions();
        //     configureAction?.Invoke(clientOptions);
        //     
        //     services.AddSingleton(clientOptions);
        //     services.AddSingleton(new UserAccessTokenManagementOptions());
        //
        //     return services.AddClientAccessTokenManagementInternal();
        // }
        //
        // /// <summary>
        // /// Adds the services required for client access token management
        // /// </summary>
        // /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        // /// <param name="configureAction">A delegate that is used to configure a <see cref="ClientAccessTokenManagementOptions"/>.</param>
        // /// <returns></returns>
        // /// <remarks>
        // /// The <see cref="IServiceProvider"/> provided to <paramref name="configureAction"/> will be the
        // /// same application's root service provider instance.
        // /// </remarks>
        // public static TokenManagementBuilder AddClientAccessTokenManagement(
        //     this IServiceCollection services,
        //     Action<IServiceProvider, ClientAccessTokenManagementOptions> configureAction)
        // {
        //     CheckConfigMarker(services);
        //
        //     services.AddSingleton(provider =>
        //     {
        //         var clientOptions = new ClientAccessTokenManagementOptions();
        //         configureAction?.Invoke(provider, clientOptions);
        //
        //         return clientOptions;
        //     });
        //
        //     services.AddSingleton(new UserAccessTokenManagementOptions());
        //
        //     return services.AddClientAccessTokenManagementInternal();
        // }
        //
        //
        //
        // private static void AddSharedServices(this IServiceCollection services)
        // {
        //     services.TryAddTransient<ITokenClientConfigurationService, DefaultTokenClientConfigurationService>();
        //     services.TryAddTransient<ITokenEndpointService, TokenEndpointService>();
        //     
        //     services.AddHttpClient(AccessTokenManagementDefaults.BackChannelHttpClientName);
        // }
        //
        //
        //
        /// <summary>
        /// Adds a named HTTP client for the factory that automatically sends the a client access token
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        /// <param name="clientName">The name of the client.</param>
        /// <param name="tokenClientName">The name of the token client.</param>
        /// <param name="configureClient">A delegate that is used to configure a <see cref="HttpClient"/>.</param>
        /// <returns></returns>
        public static IHttpClientBuilder AddClientCredentialsAccessTokenHttpClient(
            this IServiceCollection services, string clientName,
            string tokenClientName = TokenManagementDefaults.DefaultTokenClientName,
            Action<HttpClient>? configureClient = null)
        {
            if (configureClient != null)
            {
                return services.AddHttpClient(clientName, configureClient)
                    .AddClientAccessTokenHandler(tokenClientName);
            }

            return services.AddHttpClient(clientName)
                .AddClientAccessTokenHandler(tokenClientName);
        }

        //
        /// <summary>
        /// Adds a named HTTP client for the factory that automatically sends the a client access token
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/>.</param>
        /// <param name="clientName">The name of the client.</param>
        /// <param name="tokenClientName">The name of the token client.</param>
        /// <param name="configureClient">Additional configuration with service provider instance.</param>
        /// <returns></returns>
        public static IHttpClientBuilder AddClientAccessTokenHttpClient(
            this IServiceCollection services,
            string clientName,
            string tokenClientName = TokenManagementDefaults.DefaultTokenClientName,
            Action<IServiceProvider, HttpClient>? configureClient = null)
        {
            if (configureClient != null)
            {
                return services.AddHttpClient(clientName, configureClient)
                    .AddClientAccessTokenHandler(tokenClientName);
            }

            return services.AddHttpClient(clientName)
                .AddClientAccessTokenHandler(tokenClientName);
        }

        //
        /// <summary>
        /// Adds the client access token handler to an HttpClient
        /// </summary>
        /// <param name="httpClientBuilder"></param>
        /// <param name="tokenClientName"></param>
        /// <returns></returns>
        public static IHttpClientBuilder AddClientAccessTokenHandler(
            this IHttpClientBuilder httpClientBuilder,
            string tokenClientName = TokenManagementDefaults.DefaultTokenClientName)
        {
            return httpClientBuilder.AddHttpMessageHandler(provider =>
            {
                var accessTokenManagementService = provider.GetRequiredService<IClientCredentialsTokenManagementService>();

                return new ClientCredentialsAccessTokenHandler(accessTokenManagementService, tokenClientName);
            });
        }
        //
        //
        //
        // private static TokenManagementBuilder AddClientAccessTokenManagementInternal(this IServiceCollection services)
        // {
        //     // necessary ASP.NET plumbing
        //     services.AddDistributedMemoryCache();
        //     services.TryAddSingleton<ISystemClock, SystemClock>();
        //     services.TryAddSingleton<IAuthenticationSchemeProvider, AuthenticationSchemeProvider>();
        //     
        //     services.AddSharedServices();
        //     
        //     services.TryAddTransient<IClientAccessTokenManagementService, ClientAccessTokenManagementService>();
        //     services.TryAddTransient<IClientAccessTokenCache, ClientAccessTokenCache>();
        //     services.TryAddSingleton<IClientAccessTokenRequestSynchronization, AccessTokenRequestSynchronization>();
        //     
        //     return new TokenManagementBuilder(services);
        // }
        //
        //
    }
}