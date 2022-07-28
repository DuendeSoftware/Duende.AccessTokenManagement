// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Duende.AccessTokenManagement;

/// <summary>
/// Default values
/// </summary>
public static class ClientCredentialsTokenManagementDefaults
{
    /// <summary>
    /// Name of the back-channel HTTP client
    /// </summary>
    public const string BackChannelHttpClientName = "Duende.AccessTokenManagement.BackChannelHttpClient";
        
    /// <summary>
    /// Name used to propagate access token parameters to HttpRequestMessage
    /// </summary>
    public const string TokenRequestParametersOptionsName = "Duende.AccessTokenManagement.AccessTokenParameters";
}