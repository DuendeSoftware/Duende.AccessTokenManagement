using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using System;
using Duende.AccessTokenManagement;
using Serilog.Sinks.SystemConsole.Themes;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text.Json;

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

                services.AddClientCredentialsTokenManagement()
                    .AddClient("demo", client =>
                    {
                        client.TokenEndpoint = "https://demo.duendesoftware.com/connect/token";

                        client.ClientId = "m2m.short";
                        client.ClientSecret = "secret";

                        client.Scope = "api";
                    })
                    .AddClient("demo.dpop", client =>
                    {
                        client.TokenEndpoint = "https://demo.duendesoftware.com/connect/token";
                        //client.TokenEndpoint = "https://localhost:5001/connect/token";

                        client.ClientId = "m2m.dpop";
                        //client.ClientId = "m2m.dpop.nonce";
                        client.ClientSecret = "secret";

                        client.Scope = "api";
                        client.DPoPJsonWebKey = CreateDPoPKey();
                    })
                    .AddClient("demo.jwt", client =>
                    {
                        client.TokenEndpoint = "https://demo.duendesoftware.com/connect/token";
                        client.ClientId = "m2m.short.jwt";

                        client.Scope = "api";
                    });

                services.AddClientCredentialsHttpClient("client", "demo", client =>
                {
                    client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/");
                });

                services.AddClientCredentialsHttpClient("client.dpop", "demo.dpop", client =>
                {
                    //client.BaseAddress = new Uri("https://localhost:5001/api/dpop/");
                    client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/dpop/");
                });

                services.AddHttpClient<TypedClient>(client =>
                    {
                        client.BaseAddress = new Uri("https://demo.duendesoftware.com/api/");
                    })
                    .AddClientCredentialsTokenHandler("demo");

                services.AddTransient<IClientAssertionService, ClientAssertionService>();

                //services.AddHostedService<WorkerManual>();
                //services.AddHostedService<WorkerManualJwt>();
                //services.AddHostedService<WorkerHttpClient>();
                //services.AddHostedService<WorkerTypedHttpClient>();
                services.AddHostedService<WorkerDPoPHttpClient>();
            });

        return host;
    }

    private static string CreateDPoPKey()
    {
        var key = new RsaSecurityKey(RSA.Create(2048));
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(key);
        jwk.Alg = "PS256";
        var jwkJson = JsonSerializer.Serialize(jwk);
        return jwkJson;
    }

}