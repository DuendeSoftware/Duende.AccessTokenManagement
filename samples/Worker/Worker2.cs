using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Duende.TokenManagement.ClientCredentials;
using IdentityModel.Client;

namespace WorkerService;

public class Worker2 : BackgroundService
{
    private readonly ILogger<Worker2> _logger;
    private readonly IHttpClientFactory _clientFactory;
    private readonly IClientCredentialsTokenManagementService _tokenManagementService;

    public Worker2(ILogger<Worker2> logger, IHttpClientFactory factory, IClientCredentialsTokenManagementService tokenManagementService)
    {
        _logger = logger;
        _clientFactory = factory;
        _tokenManagementService = tokenManagementService;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(3000, stoppingToken);
            
        while (!stoppingToken.IsCancellationRequested)
        {
            Console.WriteLine("\n\n");
            _logger.LogInformation("Worker2 running at: {time}", DateTimeOffset.Now);

            var client = _clientFactory.CreateClient();
            client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/");
            
            var token = await _tokenManagementService.GetAccessTokenAsync("demo");
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