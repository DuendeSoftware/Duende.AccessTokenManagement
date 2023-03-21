// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Duende.AccessTokenManagement;
using IdentityModel.Client;

namespace WorkerService;

public class WorkerManual : BackgroundService
{
    private readonly ILogger<WorkerManual> _logger;
    private readonly IHttpClientFactory _clientFactory;
    private readonly IClientCredentialsTokenManagementService _tokenManagementService;

    public WorkerManual(ILogger<WorkerManual> logger, IHttpClientFactory factory, IClientCredentialsTokenManagementService tokenManagementService)
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
            _logger.LogInformation("WorkerManual running at: {time}", DateTimeOffset.Now);

            var client = _clientFactory.CreateClient();
            client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/");
            
            var token = await _tokenManagementService.GetAccessTokenAsync("demo");
            client.SetBearerToken(token.AccessToken!);
            
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