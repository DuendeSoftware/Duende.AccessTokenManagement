using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Duende.TokenManagement.OpenIdConnect;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;

namespace MvcCode.Controllers;

public class HomeController : Controller
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IUserTokenManagementService _tokenManagementService;

    public HomeController(IHttpClientFactory httpClientFactory, IUserTokenManagementService tokenManagementService)
    {
        _httpClientFactory = httpClientFactory;
        _tokenManagementService = tokenManagementService;
    }

    [AllowAnonymous]
    public IActionResult Index() => View();

    public IActionResult Secure() => View();

    public IActionResult Logout() => SignOut("cookie", "oidc");

    public async Task<IActionResult> CallApiAsUserManual()
    {
        var token = await _tokenManagementService.GetAccessTokenAsync(User);
        var client = _httpClientFactory.CreateClient();
        client.SetBearerToken(token.Value);
            
        var response = await client.GetStringAsync("https://demo.duendesoftware.com/api/test");
        ViewBag.Json = PrettyPrint(response);

        return View("CallApi");
    }
        
    public async Task<IActionResult> CallApiAsUserExtensionMethod()
    {
        var token = await HttpContext.GetUserAccessTokenAsync();
        var client = _httpClientFactory.CreateClient();
        client.SetBearerToken(token.Value);
            
        var response = await client.GetStringAsync("https://demo.duendesoftware.com/api/test");
        ViewBag.Json = PrettyPrint(response);

        return View("CallApi");
    }
        
    public async Task<IActionResult> CallApiAsUser()
    {
        var client = _httpClientFactory.CreateClient("user_client");

        var response = await client.GetStringAsync("test");
        //ViewBag.Json = JArray.Parse(response).ToString();

        return View("CallApi");
    }

    public async Task<IActionResult> CallApiAsUserTyped([FromServices] TypedUserClient client)
    {
        var response = await client.CallApi();
        //ViewBag.Json = JArray.Parse(response).ToString();

        return View("CallApi");
    }

    [AllowAnonymous]
    public async Task<IActionResult> CallApiAsClient()
    {
        var client = _httpClientFactory.CreateClient("client");

        var response = await client.GetStringAsync("test");
        //ViewBag.Json = JArray.Parse(response).ToString();

        return View("CallApi");
    }

    [AllowAnonymous]
    public async Task<IActionResult> CallApiAsClientTyped([FromServices] TypedClientClient client)
    {
        var response = await client.CallApi();
        //ViewBag.Json = JArray.Parse(response).ToString();

        return View("CallApi");
    }

    string PrettyPrint(string json)
    {
        var doc = JsonDocument.Parse(json).RootElement;
        return JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
    }
}