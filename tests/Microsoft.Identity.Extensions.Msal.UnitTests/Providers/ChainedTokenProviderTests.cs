// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Core;
using Microsoft.Identity.Client.Instance;
using Microsoft.Identity.Extensions.Msal.Providers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Identity.Extensions.Providers
{
    [TestClass]
    public class ChainedTokenProviderTests
    {
        [TestInitialize]
        public void TestInitialize()
        {
        }

        [TestMethod]
        [TestCategory("ChainedTokenProviderTests")]
        public async Task SelectTheFirstAvailableProbeTestAsync()
        {
            var probes = new List<IProbe>
            {
                new MockProbe{ Available = false, Provider = new MockProvider() },
                new MockProbe{ Available = false, Provider = new MockProvider() },
                new MockProbe{ Available = true, Provider = new MockProvider{ Token = new MockToken{ AccessToken = "foo", ExpiresOn = DateTime.UtcNow.AddSeconds(60)} } },
                new MockProbe{ Available = true, Provider = new MockProvider{ Token = new MockToken{ AccessToken = "bar", ExpiresOn = DateTime.UtcNow.AddSeconds(60)} } },
            };
            var chain = new TokenProviderChain(probes);

            var token = await chain.GetTokenAsync(new List<string> { "something" }).ConfigureAwait(false);
            Assert.AreEqual("foo", token.AccessToken);
        }

        [TestMethod]
        [TestCategory("ChainedTokenProviderTests")]
        public async Task NoAvailableProbesTestAsync()
        {
            var probes = new List<IProbe>
            {
                new MockProbe{ Available = false, Provider = new MockProvider() },
            };
            var chain = new TokenProviderChain(probes);

            await Assert.ThrowsExceptionAsync<NoProbesAvailableException>(async () => await chain.GetTokenAsync(new List<string> { "something" }).ConfigureAwait(false)).ConfigureAwait(false);
        }
    }
#pragma warning disable CS1998 // Async method lacks 'await' operators and will run synchronously
    public class MockProbe : IProbe
    {
        public ITokenProvider Provider { get; set; }

        public bool Available { get; set; }


        public async Task<bool> AvailableAsync() => Available;


        public async Task<ITokenProvider> ProviderAsync() => Provider;
    }

    public class MockProvider : ITokenProvider
    {
        public IToken Token { get; set; }

        public async Task<IToken> GetTokenAsync(IEnumerable<string> scopes = null) => Token;
    }

    public class MockToken : IToken
    {
        public DateTimeOffset? ExpiresOn { get; set; }

        public string AccessToken { get; set; }
    }
#pragma warning restore CS1998 // Async method lacks 'await' operators and will run synchronously
}
