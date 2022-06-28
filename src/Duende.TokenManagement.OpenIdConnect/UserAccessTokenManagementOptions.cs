using System;
using IdentityModel.Client;

namespace Duende.TokenManagement.OpenIdConnect
{
    /// <summary>
    /// Options for user access token management
    /// </summary>
    public class UserAccessTokenManagementOptions
    {
        /// <summary>
        /// Default client credential style to use when requesting tokens
        /// </summary>
        public ClientCredentialStyle ClientCredentialStyle { get; set; } =
            ClientCredentialStyle.PostBody;
        
        /// <summary>
        /// Name of the authentication scheme to use for deriving token service configuration
        /// (will fall back to configured default challenge scheme if not set)
        /// </summary>
        public string? SchemeName { get; set; }

        /// <summary>
        /// Timespan that specifies how long before expiration, the token should be refreshed (defaults to 1 minute)
        /// </summary>
        public TimeSpan RefreshBeforeExpiration { get; set; } = TimeSpan.FromMinutes(1);
        
        /// <summary>
        /// Scope value when requesting a client credentials token.
        /// If not set, token request will omit scope parameter.
        /// </summary>
        public string? ClientCredentialsScope { get; set; }
            
        /// <summary>
        /// Resource value when requesting a client credentials token.
        /// If not set, token request will omit resource parameter.
        /// </summary>
        public string? ClientCredentialsResource { get; set; }
    }
}