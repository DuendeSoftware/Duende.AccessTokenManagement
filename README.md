## About Duende.AccessTokenManagement
This is the repository for a set of .NET libraries that manage OAuth and OpenId
Connect access tokens. These tools automatically acquire new tokens when old
tokens are about to expire, provide conveniences for using the current token
with HTTP clients, and can revoke tokens that are no longer needed.

## Packages
The libraries in this repository are distributed as NuGet packages.

- [Duende.AccessTokenManagement](https://www.nuget.org/packages/Duende.AccessTokenManagement) manages tokens acquired in machine-to-machine flows in 
[.NET workers](https://learn.microsoft.com/en-us/dotnet/core/extensions/workers) and [ASP.NET Core worker services](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/host/hosted-services).
- [Duende.AccessTokenManagement.OpenIdConnect](https://www.nuget.org/packages/Duende.AccessTokenManagement.OpenIdConnect)
manages tokens acquired in user-centric flows in [ASP.NET Core](https://dotnet.microsoft.com/en-us/apps/aspnet)
applications.

## Documentation
Documentation is available [here](https://github.com/DuendeSoftware/Duende.AccessTokenManagement/wiki).

## License and Feedback
Duende.AccessTokenManagement is released as open source under the 
[Apache 2.0 license](https://github.com/DuendeSoftware/Duende.AccessTokenManagement/blob/main/LICENSE). 
[Bug reports, feature requests](https://github.com/DuendeSoftware/Duende.AccessTokenManagement/issues) and 
[contributions](https://github.com/DuendeSoftware/Duende.AccessTokenManagement/pulls) are welcome. 
If you have an idea for a new feature or significant code change you'd like to propose, please start with a 
GitHub issue so that we can discuss it. Thanks in advance!