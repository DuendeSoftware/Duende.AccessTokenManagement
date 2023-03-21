using System;
using Microsoft.Extensions.Options;

namespace Duende.AccessTokenManagement
{
    /// <summary>
    /// Named options to allow dependency injection for client configuration
    /// </summary>
    internal class ConfigureClientCredentialsOptions : IConfigureNamedOptions<ClientCredentialsClient>
    {
        private readonly string _name;
        private readonly IServiceProvider _serviceProvider;
        private readonly Action<IServiceProvider, ClientCredentialsClient> _configureOptions;

        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="name"></param>
        /// <param name="serviceProvider"></param>
        /// <param name="configureOptions"></param>
        public ConfigureClientCredentialsOptions(string name, IServiceProvider serviceProvider, Action<IServiceProvider, ClientCredentialsClient> configureOptions)
        {
            _name = name;
            _serviceProvider = serviceProvider;
            _configureOptions = configureOptions;
        }

        /// <inheritdoc />
        public void Configure(ClientCredentialsClient options)
        { }

        /// <inheritdoc />
        public void Configure(string? name, ClientCredentialsClient options)
        {
            if (name == _name)
            {
                _configureOptions(_serviceProvider, options);
            }
        }
    }
}
