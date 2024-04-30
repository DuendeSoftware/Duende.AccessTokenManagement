// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Security.Claims;
using System.Threading.Tasks;

namespace Duende.AccessTokenManagement.OpenIdConnect;

/// <summary>
/// Service that retrieves the current principal.
/// </summary>
public interface IUserAccessor
{
    /// <summary>
    /// Gets the current user.
    /// </summary>
    Task<ClaimsPrincipal> GetCurrentUserAsync();
}
