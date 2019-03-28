// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.Identity.Client;
using Microsoft.Identity.Client.AppConfig;
using Microsoft.Identity.Client.Core;
using Microsoft.Identity.Client.Http;
using Microsoft.Identity.Client.Instance;
using Microsoft.Identity.Extensions.Msal.Providers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

namespace Microsoft.Identity.Extensions.Providers
{
    [TestClass]
    public class ServicePrincipalTests
    {
        private static readonly Responder DiscoveryResponder = new Responder
        {
            Matcher = (req, state) => req.RequestUri.ToString().StartsWith("https://login.microsoftonline.com/common/discovery/instance"),
            MockResponse = (req, state) =>
            {
                const string content = @"{
                        ""tenant_discovery_endpoint"":""https://login.microsoftonline.com/tenant/.well-known/openid-configuration"",
                        ""api-version"":""1.1"",
                        ""metadata"":[
                            {
                            ""preferred_network"":""login.microsoftonline.com"",
                            ""preferred_cache"":""login.windows.net"",
                            ""aliases"":[
                                ""login.microsoftonline.com"",
                                ""login.windows.net"",
                                ""login.microsoft.com"",
                                ""sts.windows.net""]},
                            {
                            ""preferred_network"":""login.partner.microsoftonline.cn"",
                            ""preferred_cache"":""login.partner.microsoftonline.cn"",
                            ""aliases"":[
                                ""login.partner.microsoftonline.cn"",
                                ""login.chinacloudapi.cn""]},
                            {
                            ""preferred_network"":""login.microsoftonline.de"",
                            ""preferred_cache"":""login.microsoftonline.de"",
                            ""aliases"":[
                                    ""login.microsoftonline.de""]},
                            {
                            ""preferred_network"":""login.microsoftonline.us"",
                            ""preferred_cache"":""login.microsoftonline.us"",
                            ""aliases"":[
                                ""login.microsoftonline.us"",
                                ""login.usgovcloudapi.net""]},
                            {
                            ""preferred_network"":""login-us.microsoftonline.com"",
                            ""preferred_cache"":""login-us.microsoftonline.com"",
                            ""aliases"":[
                                ""login-us.microsoftonline.com""]}
                        ]
                    }";
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new MockJsonContent(content)
                };
            }
        };

        private static readonly Func<string, Responder> TenantDiscoveryResponder = (authority) =>
        {
            return new Responder
            {
                Matcher = (req, state) => req.RequestUri.ToString() == authority + "v2.0/.well-known/openid-configuration",
                MockResponse = (req, state) =>
                {
                    var qp = "";
                    var authorityUri = new Uri(authority);
                    var path = authorityUri.AbsolutePath.Substring(1);
                    var tenant = path.Substring(0, path.IndexOf("/", StringComparison.Ordinal));
                    if (tenant.ToLowerInvariant().Equals("common", StringComparison.OrdinalIgnoreCase))
                    {
                        tenant = "{tenant}";
                    }

                    if (!string.IsNullOrEmpty(qp))
                    {
                        qp = "?" + qp;
                    }

                    var content = string.Format(CultureInfo.InvariantCulture,
                        "{{\"authorization_endpoint\":\"{0}oauth2/v2.0/authorize{2}\",\"token_endpoint\":\"{0}oauth2/v2.0/token{2}\",\"issuer\":\"https://sts.windows.net/{1}\"}}",
                        authority, tenant, qp);
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new MockJsonContent(content)
                    };
                }
            };
        };

        private static readonly Responder ClientCredentialTokenResponder = new Responder
        {
            Matcher = (req, state) => req.RequestUri.ToString().EndsWith("oauth2/v2.0/token") && req.Method == HttpMethod.Post,
            MockResponse = (req, state) =>
            {
                const string token = "superdupertoken";
                const string tokenContent = "{\"token_type\":\"Bearer\",\"expires_in\":\"3599\",\"access_token\":\"" + token + "\"}";
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new MockJsonContent(tokenContent)
                };
            }
        };

        [TestInitialize]
        public void TestInitialize()
        {
        }

        [TestMethod]
        [TestCategory("ServicePrincipalTests")]
        public async Task ProbeShouldNotBeAvailableWithoutEnvironmentVarsAsync()
        {
            var provider = new ServicePrincipalTokenProvider(config: new ServicePrincipalConfiguration());
            Assert.IsFalse(await provider.AvailableAsync().ConfigureAwait(false));
        }

        [TestMethod]
        [TestCategory("ServicePrincipalTests")]
        public async Task ProbeShouldThrowIfNotAvailablesAsync()
        {
            var provider = new ServicePrincipalTokenProvider(config: new ServicePrincipalConfiguration());
            Assert.IsFalse(await provider.AvailableAsync().ConfigureAwait(false));
            var ex = await Assert.ThrowsExceptionAsync<InvalidOperationException>(async () => await provider.GetTokenAsync(new List<string>{"foo"})
                .ConfigureAwait(false)).ConfigureAwait(false);
            Assert.AreEqual("The required environment variables are not available.", ex.Message);
        }

        [TestMethod]
        [TestCategory("ServicePrincipalTests")]
        public async Task ProbeShouldBeAvailableWithServicePrincipalAndSecretAsync()
        {
            var provider = new ServicePrincipalTokenProvider(config: new ServicePrincipalConfiguration
            {
                ClientId = "foo",
                ClientSecret = "bar",
                TenantId = "Bazz"
            });
            Assert.IsTrue(await provider.AvailableAsync().ConfigureAwait(false));
            Assert.IsFalse(provider.IsClientCertificate());
            Assert.IsTrue(provider.IsClientSecret());
        }

        [TestMethod]
        [TestCategory("ServicePrincipalTests")]
        public async Task ProviderShouldFetchTokenWithServicePrincipalAndSecretAsync()
        {
            const string authority = "https://login.microsoftonline.com/tenantid/";
            var handler = new MockManagedIdentityHttpMessageHandler();
            handler.Responders.Add(DiscoveryResponder);
            handler.Responders.Add(TenantDiscoveryResponder(authority));
            handler.Responders.Add(ClientCredentialTokenResponder);
            var clientFactory = new ClientFactory(new HttpClient(handler));
            var clientId = Guid.NewGuid();
            var provider = new InternalServicePrincipalTokenProvider(authority, "tenantid", clientId.ToString(), "someSecret", clientFactory);
            var token = await provider.GetTokenAsync(new List<string> { @"https://management.azure.com//.default" }).ConfigureAwait(false);
            Assert.IsNotNull(token);
        }

        [TestMethod]
        [TestCategory("ServicePrincipalTests")]
        public async Task ProbeShouldBeAvailableWithServicePrincipalAndCertificateBase64Async()
        {
            var provider = new ServicePrincipalTokenProvider(config: new ServicePrincipalConfiguration
            {
                ClientId = "foo",
                CertificateBase64 = "bar",
                TenantId = "Bazz"
            });
            Assert.IsTrue(await provider.AvailableAsync().ConfigureAwait(false));
            Assert.IsTrue(provider.IsClientCertificate());
            Assert.IsFalse(provider.IsClientSecret());
        }

        [TestMethod]
        [TestCategory("ServicePrincipalTests")]
        public async Task ProbeShouldThrowIfCertificateIsNotInStoreAsync()
        {
            var cfg = new ServicePrincipalConfiguration
            {
                ClientId = "foo",
                CertificateThumbprint = "bar",
                CertificateStoreName = "My",
                TenantId = "Bazz"
            };
            var provider = new ServicePrincipalTokenProvider(config: cfg);
            var msg = $"Unable to find certificate with thumbprint '{cfg.CertificateThumbprint}' in certificate store named 'My' and store location CurrentUser";
            var ex = await Assert.ThrowsExceptionAsync<InvalidOperationException>(async () => await provider.GetTokenAsync(new List<string>{"foo"}).ConfigureAwait(false)).ConfigureAwait(false);
            Assert.AreEqual(msg, ex.Message);
        }

        [TestMethod]
        [TestCategory("ServicePrincipalTests")]
        public async Task ProbeShouldBeAvailableWithServicePrincipalAndCertificateThumbAndStoreAsync()
        {
            var provider = new ServicePrincipalTokenProvider(config: new ServicePrincipalConfiguration
            {
                ClientId = "foo",
                CertificateThumbprint = "bar",
                CertificateStoreName = "My",
                TenantId = "Bazz"
            });
            Assert.IsTrue(await provider.AvailableAsync().ConfigureAwait(false));
            Assert.IsTrue(provider.IsClientCertificate());
            Assert.IsFalse(provider.IsClientSecret());
        }

        [TestMethod]
        [TestCategory("ServicePrincipalTests")]
        public async Task ProbeShouldNotBeAvailableWithoutTenantIDAsync()
        {
            var provider = new ServicePrincipalTokenProvider(config: new ServicePrincipalConfiguration
            {
                ClientId = "foo",
                CertificateThumbprint = "bar",
                CertificateStoreName = "My",
            });
            Assert.IsFalse(await provider.AvailableAsync().ConfigureAwait(false));
        }
    }

    internal class ServicePrincipalConfiguration : IServicePrincipalConfiguration
    {
        public string ClientId { get; set; }

        public string CertificateBase64 { get; set; }

        public string CertificateThumbprint { get; set; }

        public string CertificateSubjectDistinguishedName { get; set; }

        public string CertificateStoreName { get; set; }

        public string TenantId { get; set; }

        public string ClientSecret { get; set; }

        public string CertificateStoreLocation { get; set; }

        public string Authority => "login.microsoftonline.com";

        public IMsalHttpClientFactory clientFactory { get; set; }
    }

    internal class ClientFactory : IMsalHttpClientFactory
    {
        private readonly HttpClient _client;
        public ClientFactory(HttpClient client) => _client = client;
        public HttpClient GetHttpClient() => _client;
    }
}
