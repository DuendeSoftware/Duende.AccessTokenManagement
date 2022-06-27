using System.Threading.Tasks;
using IdentityModel.Client;

namespace Duende.TokenManagement.OpenIdConnect
{
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
    }
}