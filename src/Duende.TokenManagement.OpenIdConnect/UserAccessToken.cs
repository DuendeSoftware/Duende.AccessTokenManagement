// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using Duende.TokenManagement.ClientCredentials;

namespace Duende.TokenManagement.OpenIdConnect
{
    /// <summary>
    /// Models a user access token
    /// </summary>
    public class UserAccessToken : AccessToken
    {
        /// <summary>
        /// The refresh token
        /// </summary>
        public string? RefreshToken { get; set; }
    }
}