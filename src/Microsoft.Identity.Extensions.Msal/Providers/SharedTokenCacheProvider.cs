// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Threading.Tasks;

namespace Microsoft.Identity.Extensions.Msal.Providers
{
    /// <summary>
    /// SharedTokenCacheProbe (wip) provides shared access to tokens from the Microsoft family of products.
    /// This probe will provided access to tokens from accounts that have been authenticated in other Microsoft products to provide a single sign-on experience.
    /// </summary>
    public class SharedTokenCacheProvider : ITokenProvider
    {
        /// <inheritdoc />
        public Task<bool> AvailableAsync()
        {
            throw new System.NotImplementedException();
        }

        /// <inheritdoc />
        public Task<IToken> GetTokenAsync(IEnumerable<string> scopes)
        {
            throw new System.NotImplementedException();
        }
    }
}
