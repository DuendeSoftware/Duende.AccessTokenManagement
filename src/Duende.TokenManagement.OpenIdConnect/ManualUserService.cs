// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Security.Claims;

namespace Duende.TokenManagement.OpenIdConnect;

/// <summary>
/// Implementation using manual setter/getter
/// </summary>
public class ManualUserService : IUserService
{
    private ClaimsPrincipal? _principal;

    /// <inheritdoc />
    public ClaimsPrincipal Principal
    {
        get
        {
            if (_principal == null) throw new InvalidOperationException("principal not set");
            return _principal;
        }
        set => _principal = value;
    }
}