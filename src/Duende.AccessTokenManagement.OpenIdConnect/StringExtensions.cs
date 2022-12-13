// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Duende.AccessTokenManagement.OpenIdConnect;

internal static class StringExtensions
{
    [DebuggerStepThrough]
    public static bool IsMissing(this string? value)
    {
        return string.IsNullOrWhiteSpace(value);
    }
        
    [DebuggerStepThrough]
    public static bool IsPresent(this string? value)
    {
        return !string.IsNullOrWhiteSpace(value);
    }
    
    [DebuggerStepThrough]
    public static void ThrowIfNull(this object? value, string? paramName = null, string? message = null)
    {
        if (value is null) throw new ArgumentNullException(paramName, message);
    }
}