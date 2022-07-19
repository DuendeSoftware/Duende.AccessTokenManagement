// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace WorkerService;

public class WorkerTypedHttpClient : BackgroundService
{
    private readonly ILogger<WorkerTypedHttpClient> _logger;
    private readonly TypedClient _client;

    public WorkerTypedHttpClient(ILogger<WorkerTypedHttpClient> logger, TypedClient client)
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
            _logger.LogInformation("WorkerTypedHttpClient running at: {time}", DateTimeOffset.Now);

            var response = await _client.CallApi();
            _logger.LogInformation("API response: {response}", response);    
            
            await Task.Delay(5000, stoppingToken);
        }
    }
}