using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using System;
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
                    
                services.AddClientCredentialsTokenManagement(options =>
                {
                    options.Clients.Add("demo", new()
                    {
                        Address = "https://demo.duendesoftware.com/connect/token",
                            
                        ClientId = "m2m.short",
                        ClientSecret = "secret",
                            
                        Scope = "api"
                    });
                });
                    
                services.AddClientCredentialsHttpClient("client", "demo", client =>
                {
                    client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/");
                });
                
                // services.AddHostedService<Worker1>();
                // services.AddHostedService<Worker2>();
                services.AddHostedService<Worker3>();
            });

        return host;
    }
            
}