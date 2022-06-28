using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Duende.TokenManagement.ClientCredentials;
using IdentityModel.Client;
using Microsoft.AspNetCore.Server.HttpSys;

namespace WorkerService;

public class Worker3 : BackgroundService
{
    private readonly ILogger<Worker2> _logger;
    private readonly IHttpClientFactory _clientFactory;
    private readonly IClientCredentialsTokenManagementService _tokenManagementService;

    public Worker3(ILogger<Worker2> logger, IHttpClientFactory factory, IClientCredentialsTokenManagementService tokenManagementService)
    {
        _logger = logger;
        _clientFactory = factory;
        _tokenManagementService = tokenManagementService;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(4000, stoppingToken);
            
        while (!stoppingToken.IsCancellationRequested)
        {
            Console.WriteLine("\n\n");
            _logger.LogInformation("Worker2 running at: {time}", DateTimeOffset.Now);

            var client = _clientFactory.CreateClient();
            client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/");

            var request = new ClientCredentialsTokenRequest
            {
                Address = "https://demo.duendesoftware.com/connect/token",

                ClientId = "m2m.short",
                ClientSecret = "secret",

                Scope = "api"
            };
            
            var token = await _tokenManagementService.GetAccessTokenAsync("manual", request: request);
            client.SetBearerToken(token.Value);
            
            var response = await client.GetAsync("test", stoppingToken);
                
            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync(stoppingToken);
                _logger.LogInformation("API response: {response}", content);    
            }
            else
            {
                _logger.LogError("API returned: {statusCode}", response.StatusCode);
            }

            await Task.Delay(6000, stoppingToken);
        }
    }
}