using Duende.TokenManagement.ClientCredentials;
using IdentityModel.Client;
using Microsoft.Extensions.DependencyInjection;

namespace ClientCredentialTests;

public class Configuration
{
    [Fact(Skip = "testing")]
    public async Task No_client_registered_get_token_with_default_client_should_fail()
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        
        services.AddClientCredentialsTokenManagement();

        var provider = services.BuildServiceProvider();
        var tokenManagement = provider.GetService<IClientCredentialsConfigurationService>();
        
        var request = await tokenManagement.GetClientCredentialsRequestAsync(TokenManagementDefaults.DefaultTokenClientName, new());
    }
    
    [Fact(Skip = "testing")]
    public async Task No_client_registered_get_token_with_named_client_should_fail()
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        
        services.AddClientCredentialsTokenManagement();

        var provider = services.BuildServiceProvider();
        var tokenManagement = provider.GetService<IClientCredentialsConfigurationService>();
        
        var request = await tokenManagement.GetClientCredentialsRequestAsync("unknown", new());
    }
    
    [Fact(Skip = "testing")]
    public async Task One_client_registered_get_token_with_named_client_should_fail()
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        
        services.AddClientCredentialsTokenManagement(options =>
        {
            options.Clients.Add("client1", new ClientCredentialsTokenRequest
            {
                Address = "https://token_endpoint",
                ClientId = "id",
                ClientSecret = "secret"
            });
        });
        
        var provider = services.BuildServiceProvider();
        var tokenManagement = provider.GetService<IClientCredentialsConfigurationService>();
        
        var request = await tokenManagement.GetClientCredentialsRequestAsync("unknown", new());
    }
    
    [Fact(Skip = "testing")]
    public async Task One_client_registered_get_token_with_named_client_should_succeed()
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        
        services.AddClientCredentialsTokenManagement(options =>
        {
            options.Clients.Add("client1", new ClientCredentialsTokenRequest
            {
                Address = "https://token_endpoint",
                ClientId = "id",
                ClientSecret = "secret"
            });
        });
        
        var provider = services.BuildServiceProvider();
        var tokenManagement = provider.GetService<IClientCredentialsConfigurationService>();
        
        var request = await tokenManagement.GetClientCredentialsRequestAsync("client1", new());
    }
    
    [Fact(Skip = "testing")]
    public async Task One_client_registered_via_service_configure_get_token_with_named_client_should_succeed()
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        
        services.AddClientCredentialsTokenManagement();

        services.Configure<ClientCredentialsTokenManagementOptions>(options =>
        {
            options.Clients.Add("client1", new ClientCredentialsTokenRequest
            {
                Address = "https://token_endpoint",
                ClientId = "id",
                ClientSecret = "secret"
            });
        });
        
        var provider = services.BuildServiceProvider();
        var tokenManagement = provider.GetService<IClientCredentialsConfigurationService>();
        
        var request = await tokenManagement.GetClientCredentialsRequestAsync("client1", new());
    }
    
    [Fact(Skip = "testing")]
    public async Task One_client_registered_get_token_with_default_client_should_succeed()
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        
        services.AddClientCredentialsTokenManagement(options =>
        {
            options.Clients.Add("client1", new ClientCredentialsTokenRequest
            {
                Address = "https://token_endpoint",
                ClientId = "id",
                ClientSecret = "secret"
            });
        });
        
        var provider = services.BuildServiceProvider();
        var tokenManagement = provider.GetService<IClientCredentialsConfigurationService>();
        
        var request = await tokenManagement.GetClientCredentialsRequestAsync(TokenManagementDefaults.DefaultTokenClientName, new());
    }
    
    [Fact(Skip = "testing")]
    public async Task Two_clients_registered_get_token_with_default_client_should_fail()
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        
        services.AddClientCredentialsTokenManagement(options =>
        {
            options.Clients.Add("client1", new ClientCredentialsTokenRequest
            {
                Address = "https://token_endpoint",
                ClientId = "id",
                ClientSecret = "secret"
            });
            
            options.Clients.Add("client2", new ClientCredentialsTokenRequest
            {
                Address = "https://token_endpoint",
                ClientId = "id",
                ClientSecret = "secret"
            });
        });
        
        var provider = services.BuildServiceProvider();
        var tokenManagement = provider.GetService<IClientCredentialsConfigurationService>();
        
        var request = await tokenManagement.GetClientCredentialsRequestAsync(TokenManagementDefaults.DefaultTokenClientName, new());
    }
}