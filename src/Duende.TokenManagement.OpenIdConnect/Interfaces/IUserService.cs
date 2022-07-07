// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Security.Claims;
using System.Threading.Tasks;

namespace Duende.TokenManagement.OpenIdConnect;

/// <summary>
/// returns the principal representing the current user
/// </summary>
public interface IUserService
{
    /// <summary>
    /// Gets or sets the current principal
    /// </summary>
    public ClaimsPrincipal Principal { get; set; }
}