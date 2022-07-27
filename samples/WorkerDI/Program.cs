using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using System;
using Duende.AccessTokenManagement;
using IdentityModel.Client;
using Microsoft.Extensions.Options;
using Serilog.Sinks.SystemConsole.Themes;

namespace WorkerService;

public class Program
{
    public static void Main(string[] args)
    {
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Debug()
            .WriteTo.Console(theme: AnsiConsoleTheme.Code)
            .CreateLogger();

        CreateHostBuilder(args).Build().Run();
    }

    public static IHostBuilder CreateHostBuilder(string[] args)
    {
        var host = Host.CreateDefaultBuilder(args)
            .UseSerilog()
                
            .ConfigureServices((services) =>
            {
                services.AddDistributedMemoryCache();

                services.AddClientCredentialsTokenManagement();
                services.AddSingleton(new DiscoveryCache("https://demo.duendesoftware.com"));
                services.AddSingleton<IConfigureOptions<ClientCredentialsClient>, ClientCredentialsClientConfigureOptions>();

                // alternative way to add a client
                services.Configure<ClientCredentialsClient>("demo", client =>
                {
                    client.TokenEndpoint = "https://demo.duendesoftware.com/connect/token";

                    client.ClientId = "m2m.short";
                    client.ClientSecret = "secret";

                    client.Scope = "api";
                });
                
                services.AddClientCredentialsHttpClient("client", "demo", client =>
                {
                    client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/");
                });
                
                services.AddHttpClient<TypedClient>(client =>
                    {
                        client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/");
                    })
                    .AddClientCredentialsTokenHandler("demo");

                services.AddTransient<IClientAssertionService, ClientAssertionService>();
                
                //services.AddHostedService<WorkerManual>();
                services.AddHostedService<WorkerManualJwt>();
                //services.AddHostedService<WorkerHttpClient>();
                //services.AddHostedService<WorkerTypedHttpClient>();
            });

        return host;
    }
            
}