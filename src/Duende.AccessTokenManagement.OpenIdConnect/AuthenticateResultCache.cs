// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.AspNetCore.Authentication;
using System.Collections.Generic;

/// <summary>
/// Per-request cache so that if SignInAsync is used, we won't re-read the old/cached AuthenticateResult from the handler.
/// This requires this service to be added as scoped to the DI system.
/// Be VERY CAREFUL to not accidentally capture this service for longer than the appropriate DI scope - e.g., in an HttpClient.
/// </summary>
internal class AuthenticateResultCache: Dictionary<string, AuthenticateResult>
{
}