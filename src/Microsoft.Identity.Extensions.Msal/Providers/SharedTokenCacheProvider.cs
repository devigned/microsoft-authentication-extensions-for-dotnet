// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.AppConfig;

namespace Microsoft.Identity.Extensions.Msal.Providers
{
    /// <summary>
    /// SharedTokenCacheProbe (wip) provides shared access to tokens from the Microsoft family of products.
    /// This probe will provided access to tokens from accounts that have been authenticated in other Microsoft products to provide a single sign-on experience.
    /// </summary>
    public class SharedTokenCacheProvider : ITokenProvider
    {
        private static readonly string CacheFilePath =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "msal.cache");
        private readonly IPublicClientApplication _app;
        private readonly MsalCacheHelper _cacheHelper;

        /// <inheritdoc />
        public SharedTokenCacheProvider()
        {
            var authority = string.Format(CultureInfo.InvariantCulture,
                AadAuthority.AadCanonicalAuthorityTemplate,
                AadAuthority.DefaultTrustedHost,
                "common");
            var builder = new MsalStorageCreationPropertiesBuilder(Path.GetFileName(CacheFilePath), Path.GetDirectoryName(CacheFilePath));
            builder = builder.WithMacKeyChain(serviceName: "Microsoft.Developer.IdentityService", accountName: "MSALCache");
            builder = builder.WithLinuxKeyring(
                schemaName: "msal.cache",
                collection: "default",
                secretLabel: "MSALCache",
                attribute1: new KeyValuePair<string, string>("MsalClientID", "Microsoft.Developer.IdentityService"),
                attribute2: new KeyValuePair<string, string>("MsalClientVersion", "1.0.0.0"));
            var storageCreationProperties = builder.Build();
            _app = PublicClientApplicationBuilder
                .Create("04b07795-8ddb-461a-bbee-02f9e1bf7b46")
                .WithAuthority(new Uri(authority))
                .Build();
            _cacheHelper = MsalCacheHelper.RegisterCache(_app.UserTokenCache, storageCreationProperties);
        }

        /// <inheritdoc />
        public async Task<bool> AvailableAsync()
        {
            var accounts = await _app.GetAccountsAsync().ConfigureAwait(false);
            return accounts.Any();
        }

        /// <inheritdoc />
        public async Task<IToken> GetTokenAsync(IEnumerable<string> scopes)
        {
            var accounts = (await _app.GetAccountsAsync().ConfigureAwait(false)).ToList();
            if(!accounts.Any())
            {
                throw new InvalidOperationException("there are no accounts available to acquire a token");
            }
            var res = await _app.AcquireTokenSilentAsync(scopes, accounts.First()).ConfigureAwait(false);
            return new AccessTokenWithExpiration { ExpiresOn = res.ExpiresOn, AccessToken = res.AccessToken };
        }
    }
}
