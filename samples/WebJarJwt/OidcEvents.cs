using System.Threading.Tasks;
using Duende.TokenManagement.ClientCredentials;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace WebJarJwt
{
    public class OidcEvents : OpenIdConnectEvents
    {
        private readonly IClientAssertionService _assertionService;

        public OidcEvents(IClientAssertionService assertionService)
        {
            _assertionService = assertionService;
        }
        
        public override async Task AuthorizationCodeReceived(AuthorizationCodeReceivedContext context)
        {
            var assertion = await _assertionService.GetClientAssertionAsync("default");

            context.TokenEndpointRequest!.ClientAssertionType = assertion!.Type;
            context.TokenEndpointRequest.ClientAssertion = assertion.Value;
        }

        public override async Task RedirectToIdentityProvider(RedirectContext context)
        {
            var service = _assertionService as ClientAssertionService;
            
            var request = await service.SignAuthorizeRequest(context.ProtocolMessage);
            var clientId = context.ProtocolMessage.ClientId;
            var redirectUri = context.ProtocolMessage.RedirectUri;
            
            context.ProtocolMessage.Parameters.Clear();
            context.ProtocolMessage.ClientId = clientId;
            context.ProtocolMessage.RedirectUri = redirectUri;
            context.ProtocolMessage.SetParameter("request", request);
        }
    }
}