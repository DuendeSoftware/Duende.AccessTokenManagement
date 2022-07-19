// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Duende.AccessTokenManagement.OpenIdConnect;

internal static class StringExtensions
{
    [DebuggerStepThrough]
    public static bool IsMissing([NotNullWhen(false)]this string? value)
    {
        return string.IsNullOrWhiteSpace(value);
    }
        
    [DebuggerStepThrough]
    public static bool IsPresent([NotNullWhen(true)]this string? value)
    {
        return !string.IsNullOrWhiteSpace(value);
    }

}