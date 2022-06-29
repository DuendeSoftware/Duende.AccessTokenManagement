using System.Threading.Tasks;
using Duende.TokenManagement.ClientCredentials;
using IdentityModel.Client;

namespace Duende.TokenManagement.OpenIdConnect;

/// <summary>
/// Retrieves request details for client credentials, refresh and revocation requests
/// </summary>
public interface IUserTokenConfigurationService
{
    /// <summary>
    /// Returns the request details for a refresh token request
    /// </summary>
    /// <returns></returns>
    Task<RefreshTokenRequest> GetRefreshTokenRequestAsync(UserAccessTokenRequestParameters requestParameters);

    /// <summary>
    /// Returns the request details for a token revocation request
    /// </summary>
    /// <returns></returns>
    Task<TokenRevocationRequest> GetTokenRevocationRequestAsync(UserAccessTokenRequestParameters requestParameters);

    /// <summary>
    /// Returns a client credentials token request with inferred configuration from the OpenID Connect handler
    /// </summary>
    /// <param name="parameters"></param>
    /// <returns></returns>
    Task<ClientCredentialsTokenRequest> GetClientCredentialsRequestAsync(ClientCredentialsTokenRequestParameters parameters);
}