using Duende.AccessTokenManagement.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace BlazorServer.Plumbing;

public class OidcEvents : OpenIdConnectEvents
{
    private readonly IUserTokenStore _store;

    public OidcEvents(IUserTokenStore store)
    {
        _store = store;
    }
    
    public override async Task TokenValidated(TokenValidatedContext context)
    {
        var exp = DateTimeOffset.UtcNow.AddSeconds(Double.Parse(context.TokenEndpointResponse!.ExpiresIn));

        await _store.StoreTokenAsync(context.Principal!, new UserAccessToken
        {
            Value = context.TokenEndpointResponse.AccessToken,
            Expiration = exp,
            RefreshToken = context.TokenEndpointResponse.RefreshToken,
            Scope = context.TokenEndpointResponse.Scope
        });
        
        await base.TokenValidated(context);
    }
}