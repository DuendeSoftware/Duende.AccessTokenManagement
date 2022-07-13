using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Duende.TokenManagement.OpenIdConnect;

public interface IOpenIdConnectConfigurationService
{
    public Task<(OpenIdConnectOptions options, OpenIdConnectConfiguration configuration)>
        GetOpenIdConnectConfigurationAsync(string? schemeName = null);
}