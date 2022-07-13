using System.Threading.Tasks;

namespace Duende.TokenManagement.OpenIdConnect;

public interface IOpenIdConnectConfigurationService
{
    public Task<OpenIdConnectClientConfiguration> GetOpenIdConnectConfigurationAsync(string? schemeName = null);
}