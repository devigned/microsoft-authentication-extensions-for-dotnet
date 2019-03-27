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
        public static Responder DiscoveryResponder = new Responder
        {
            Matcher = (req, state) =>
            {
                return req.RequestUri.ToString().StartsWith("https://login.microsoftonline.com/common/discovery/instance");
            },
            MockResponse = (req, state) =>
            {
                var content = @"{
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

        public static Func<string, Responder> TenantDiscoveryResponder = (authority) =>
        {
            return new Responder
            {
                Matcher = (req, state) =>
                {
                    return req.RequestUri.ToString() == authority + "v2.0/.well-known/openid-configuration";
                },
                MockResponse = (req, state) =>
                {
                    var qp = "";
                    var authorityUri = new Uri(authority);
                    string path = authorityUri.AbsolutePath.Substring(1);
                    string tenant = path.Substring(0, path.IndexOf("/", StringComparison.Ordinal));
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

        public static Responder ClientCredentialTokenResponder = new Responder
        {
            Matcher = (req, state) =>
            {
                return req.RequestUri.ToString().EndsWith("oauth2/v2.0/token") && req.Method == HttpMethod.Post;
            },
            MockResponse = (req, state) =>
            {
                var token = "superdupertoken";
                var tokenContent = "{\"token_type\":\"Bearer\",\"expires_in\":\"3599\",\"access_token\":\"" + token + "\"}";
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
            var probe = new ServicePrincipalProbe(config: new ServicePrincipalConfiguration { });
            Assert.IsFalse(await probe.AvailableAsync().ConfigureAwait(false));
        }

        [TestMethod]
        [TestCategory("ServicePrincipalTests")]
        public async Task ProbeShouldThrowIfNotAvailablesAsync()
        {
            var probe = new ServicePrincipalProbe(config: new ServicePrincipalConfiguration { });
            Assert.IsFalse(await probe.AvailableAsync().ConfigureAwait(false));
            var ex = await Assert.ThrowsExceptionAsync<InvalidOperationException>(async () => await probe.ProviderAsync().ConfigureAwait(false)).ConfigureAwait(false);
            Assert.AreEqual("The required environment variables are not available.", ex.Message);
        }

        [TestMethod]
        [TestCategory("ServicePrincipalTests")]
        public async Task ProbeShouldBeAvailableWithServicePrincipalAndSecretAsync()
        {
            var probe = new ServicePrincipalProbe(config: new ServicePrincipalConfiguration
            {
                ClientId = "foo",
                ClientSecret = "bar",
                TenantId = "Bazz"
            });
            Assert.IsTrue(await probe.AvailableAsync().ConfigureAwait(false));
            Assert.IsFalse(probe.IsClientCertificate());
            Assert.IsTrue(probe.IsClientSecret());
        }

        [TestMethod]
        [TestCategory("ServicePrincipalTests")]
        public async Task ProviderShouldFetchTokenWithServicePrincipalAndSecretAsync()
        {
            var authority = "https://login.microsoftonline.com/tenantid/";
            var handler = new MockManagedIdentityHttpMessageHandler();
            handler.Responders.Add(DiscoveryResponder);
            handler.Responders.Add(TenantDiscoveryResponder(authority));
            handler.Responders.Add(ClientCredentialTokenResponder);
            var clientFactory = new ClientFactory(new HttpClient(handler));
            var clientID = Guid.NewGuid();
            var provider = new ServicePrincipalTokenProvider(authority, "tenantid", clientID.ToString(), "someSecret", clientFactory);
            var token = await provider.GetTokenAsync(new List<string> { @"https://management.azure.com//.default" }).ConfigureAwait(false);
            Assert.IsNotNull(token);
        }

        [TestMethod]
        [TestCategory("ServicePrincipalTests")]
        public async Task ProbeShouldBeAvailableWithServicePrincipalAndCertificateBase64Async()
        {
            var probe = new ServicePrincipalProbe(config: new ServicePrincipalConfiguration
            {
                ClientId = "foo",
                CertificateBase64 = "bar",
                TenantId = "Bazz"
            });
            Assert.IsTrue(await probe.AvailableAsync().ConfigureAwait(false));
            Assert.IsTrue(probe.IsClientCertificate());
            Assert.IsFalse(probe.IsClientSecret());
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
            var probe = new ServicePrincipalProbe(config: cfg);
            var msg = $"Unable to find certificate with thumbprint '{cfg.CertificateThumbprint}' in certificate store named 'My' and store location CurrentUser";
            var ex = await Assert.ThrowsExceptionAsync<InvalidOperationException>(async () => await probe.ProviderAsync().ConfigureAwait(false)).ConfigureAwait(false);
            Assert.AreEqual(msg, ex.Message);
        }

        [TestMethod]
        [TestCategory("ServicePrincipalTests")]
        public async Task ProbeShouldBeAvailableWithServicePrincipalAndCertificateThumbAndStoreAsync()
        {
            var probe = new ServicePrincipalProbe(config: new ServicePrincipalConfiguration
            {
                ClientId = "foo",
                CertificateThumbprint = "bar",
                CertificateStoreName = "My",
                TenantId = "Bazz"
            });
            Assert.IsTrue(await probe.AvailableAsync().ConfigureAwait(false));
            Assert.IsTrue(probe.IsClientCertificate());
            Assert.IsFalse(probe.IsClientSecret());
        }

        [TestMethod]
        [TestCategory("ServicePrincipalTests")]
        public async Task ProbeShouldNotBeAvailableWithoutTenantIDAsync()
        {
            var probe = new ServicePrincipalProbe(config: new ServicePrincipalConfiguration
            {
                ClientId = "foo",
                CertificateThumbprint = "bar",
                CertificateStoreName = "My",
            });
            Assert.IsFalse(await probe.AvailableAsync().ConfigureAwait(false));
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
