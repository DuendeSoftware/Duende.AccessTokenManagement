// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using Duende.AccessTokenManagement;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Builder for client credential clients
/// </summary>
public class ClientCredentialsTokenManagementBuilder
{
    private readonly IServiceCollection _services;

    /// <summary>
    /// ctor
    /// </summary>
    /// <param name="services"></param>
    public ClientCredentialsTokenManagementBuilder(IServiceCollection services)
    {
        _services = services;
    }

    /// <summary>
    /// Adds a client credentials client to the token management system
    /// </summary>
    /// <param name="name"></param>
    /// <param name="configureOptions"></param>
    /// <returns></returns>
    public ClientCredentialsTokenManagementBuilder AddClient(string name, Action<ClientCredentialsClient> configureOptions)
    {
        _services.Configure(name, configureOptions);
        return this;
    }
}