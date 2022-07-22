using Microsoft.Extensions.DependencyInjection;

namespace ClientCredentialTests;

public class UserTokenManagementTests
{
    [Fact]
    public async Task Foo()
    {
        var services = new ServiceCollection();

        services.AddDistributedMemoryCache();
        services.AddAuthentication();

    }
}