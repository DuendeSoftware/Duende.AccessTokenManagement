using Duende.TokenManagement.OpenIdConnect;
using IdentityModel.Client;
using Microsoft.AspNetCore.Components.Authorization;

namespace BlazorServer;

public class ApiClient
{
    private readonly HttpClient _client;
    private readonly IUserTokenManagementService _tokens;
    private readonly AuthenticationStateProvider _authenticationStateProvider;

    public ApiClient(HttpClient client, IUserTokenManagementService tokens, AuthenticationStateProvider authenticationStateProvider)
    {
        _client = client;
        _tokens = tokens;
        _authenticationStateProvider = authenticationStateProvider;
    }

    public async Task<string> CallRemoteApi()
    {
        var state = await _authenticationStateProvider.GetAuthenticationStateAsync();
        var token = await _tokens.GetAccessTokenAsync(state.User);

        //var _client = new HttpClient();
        _client.SetBearerToken(token.Value);

        return await _client.GetStringAsync("https://demo.duendesoftware.com/api/test");
    }
}