using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace WorkerService;

public class Worker4 : BackgroundService
{
    private readonly ILogger<Worker4> _logger;
    private readonly TypedClient _client;

    public Worker4(ILogger<Worker4> logger, TypedClient client)
    {
        _logger = logger;
        _client = client;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(2000, stoppingToken);
            
        while (!stoppingToken.IsCancellationRequested)
        {
            Console.WriteLine("\n\n");
            _logger.LogInformation("Worker4 running at: {time}", DateTimeOffset.Now);

            var response = await _client.CallApi();
            _logger.LogInformation("API response: {response}", response);    
            
            await Task.Delay(5000, stoppingToken);
        }
    }
}