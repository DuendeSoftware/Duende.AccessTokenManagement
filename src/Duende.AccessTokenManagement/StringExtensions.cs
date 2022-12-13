// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Duende.AccessTokenManagement;

internal static class StringExtensions
{
    [DebuggerStepThrough]
    public static void ThrowIfNull(this string? value, string? paramName = null, string? message = null)
    {
        if (value is null) throw new ArgumentNullException(paramName, message);
    }
}