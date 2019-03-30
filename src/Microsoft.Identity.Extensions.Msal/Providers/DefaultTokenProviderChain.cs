using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.EnvironmentVariables;

namespace Microsoft.Identity.Extensions.Msal.Providers
{
    /// <summary>
    /// DefaultTokenProviderChain will attempt to build and AAD token in the following order
    ///     1) Service Principal with certificate or secret <see cref="ServicePrincipalTokenProvider"/>
    ///     2) Managed Identity for AppService or Virtual Machines <see cref="ManagedIdentityTokenProvider"/>
    ///     3) Shared Token Cache for your local developer environment <see cref="SharedTokenCacheProvider"/>
    /// </summary>
    public class DefaultTokenProviderChain : ITokenProvider
    {
        private readonly ITokenProvider _chain;

        /// <inheritdoc />
        public DefaultTokenProviderChain(IConfigurationProvider config = null)
        {
            config = config ?? new EnvironmentVariablesConfigurationProvider();
            var providers = new List<ITokenProvider>
            {
                new ServicePrincipalTokenProvider(config),
                new ManagedIdentityTokenProvider(config),
                new SharedTokenCacheProvider(config)
            };
            _chain = new TokenProviderChain(providers);
        }


        /// <inheritdoc />
        public async Task<bool> AvailableAsync()
        {
            return await _chain.AvailableAsync().ConfigureAwait(false);
        }

        /// <inheritdoc />
        public async Task<IToken> GetTokenAsync(IEnumerable<string> scopes)
        {
            return await _chain.GetTokenAsync(scopes).ConfigureAwait(false);
        }


    }
}
