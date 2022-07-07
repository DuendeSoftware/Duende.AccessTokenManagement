// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace Duende.TokenManagement.OpenIdConnect;

/// <summary>
/// Implementation using HttpContext.User
/// </summary>
public class DefaultUserService : IUserService
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    /// <summary>
    /// ctor
    /// </summary>
    public DefaultUserService(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    /// <inheritdoc />
    public ClaimsPrincipal Principal
    {
        get => _httpContextAccessor.HttpContext!.User;
        set => throw new InvalidOperationException();
    }
}