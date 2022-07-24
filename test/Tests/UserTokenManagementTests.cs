using Microsoft.Extensions.DependencyInjection;

namespace Duende.AccessTokenManagement.Tests;

public class UserTokenManagementTests : IntegrationTestBase
{
    [Fact]
    public async Task Foo()
    {
        await AppHost.LoginAsync("alice");
    }
}