using Microsoft.Extensions.Configuration;

namespace Microsoft.Identity.Extensions.Msal.Providers
{
    internal static class ConfigurationProviderExtension
    {
        public static string Get(this IConfigurationProvider config, string key)
        {
            return config.TryGet(key, out var val) ? val : null;
        }
    }
}
