// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.Identity.Client;
using Microsoft.Identity.Client.AppConfig;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Microsoft.Identity.Extensions.Msal.Providers
{
    /// <inheritdoc />
    /// <summary>
    ///     ServicePrincipalProbe looks to the application setting and environment variables to build a ICredentialProvider.
    /// </summary>
    public class ServicePrincipalTokenProvider : ITokenProvider
    {
        private readonly IServicePrincipalConfiguration _config;

        /// <summary>
        /// Create a new instance of a ServicePrincipalProbe
        /// </summary>
        /// <param name="config">optional configuration; if not specified the default configuration will use environment variables</param>
        public ServicePrincipalTokenProvider(IServicePrincipalConfiguration config = null)
        {
            _config = config ?? new DefaultServicePrincipalConfiguration();
        }

        // Async method lacks 'await' operators and will run synchronously
        /// <inheritdoc />
        public Task<bool> AvailableAsync() => Task.FromResult(IsClientSecret() || IsClientCertificate());


        /// <inheritdoc />
        public async Task<IToken> GetTokenAsync(IEnumerable<string> scopes = null)
        {
            var provider = await ProviderAsync().ConfigureAwait(false);
            return await provider.GetTokenAsync().ConfigureAwait(false);
        }

        private async Task<InternalServicePrincipalTokenProvider> ProviderAsync()
        {
            var available = await AvailableAsync().ConfigureAwait(false);
            if (!available)
            {
                throw new InvalidOperationException("The required environment variables are not available.");
            }

            var authorityWithTenant = string.Format(CultureInfo.InvariantCulture, AadAuthority.AadCanonicalAuthorityTemplate, _config.Authority, _config.TenantId);

            if (!IsClientCertificate())
            {
                return new InternalServicePrincipalTokenProvider(authorityWithTenant, _config.TenantId, _config.ClientId, _config.ClientSecret);
            }

            X509Certificate2 cert;
            if (!string.IsNullOrWhiteSpace(_config.CertificateBase64))
            {
                // If the certificate is provided as base64 encoded string in env, decode and hydrate a x509 cert
                var decoded = Convert.FromBase64String(_config.CertificateBase64);
                cert = new X509Certificate2(decoded);
            }
            else
            {
                // Try to use the certificate store
                var store = new X509Store(StoreNameWithDefault, StoreLocationFromEnv);
                store.Open(OpenFlags.ReadOnly);
                var certs = !string.IsNullOrEmpty(_config.CertificateSubjectDistinguishedName) ?
                    store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, _config.CertificateSubjectDistinguishedName, true) :
                    store.Certificates.Find(X509FindType.FindByThumbprint, _config.CertificateThumbprint, true);

                if (certs.Count < 1)
                {
                    throw new InvalidOperationException(
                        $"Unable to find certificate with thumbprint '{_config.CertificateThumbprint}' in certificate store named '{StoreNameWithDefault}' and store location {StoreLocationFromEnv}");
                }

                cert = certs[0];
            }

            return new InternalServicePrincipalTokenProvider(authorityWithTenant, _config.TenantId, _config.ClientId, cert);
        }

        private StoreLocation StoreLocationFromEnv
        {
            get
            {
                var loc = _config.CertificateStoreLocation;
                if (!string.IsNullOrWhiteSpace(loc) && Enum.TryParse(loc, true, out StoreLocation sLocation))
                {
                    return sLocation;
                }

                return StoreLocation.CurrentUser;
            }
        }

        private string StoreNameWithDefault
        {
            get
            {
                var name = _config.CertificateStoreName;
                return string.IsNullOrWhiteSpace(name) ? "My" : name;
            }
        }

        internal bool IsClientSecret()
        {
            var vars = new List<string> { _config.TenantId, _config.ClientId, _config.ClientSecret };
            return vars.All(item => !string.IsNullOrWhiteSpace(item));
        }

        internal bool IsClientCertificate()
        {
            var tenantAndClient = new List<string> { _config.TenantId, _config.ClientId };
            if (tenantAndClient.All(item => !string.IsNullOrWhiteSpace(item)))
            {
                return !string.IsNullOrWhiteSpace(_config.CertificateBase64) ||
                       !string.IsNullOrWhiteSpace(_config.CertificateThumbprint);
            }

            return false;
        }
    }

    /// <summary>
    /// IManagedIdentityConfiguration provides the configurable properties for the ManagedIdentityProbe
    /// </summary>
    public interface IServicePrincipalConfiguration
    {
        /// <summary>
        /// CertificateBase64 is the base64 encoded representation of an x509 certificate
        /// </summary>
        string CertificateBase64 { get; }

        /// <summary>
        /// CertificateThumbprint is the thumbprint of the certificate in the Windows Certificate Store
        /// </summary>
        string CertificateThumbprint { get; }

        /// <summary>
        /// CertificateSubjectDistinguishedName is the subject distinguished name of the certificate in the Windows Certificate Store
        /// </summary>
        string CertificateSubjectDistinguishedName { get; }

        /// <summary>
        /// CertificateStoreName is the name of the certificate store on Windows where the certificate is stored
        /// </summary>
        string CertificateStoreName { get; }

        /// <summary>
        /// CertificateStoreLocation is the location of the certificate store on Windows where the certificate is stored
        /// </summary>
        string CertificateStoreLocation { get; }

        /// <summary>
        /// TenantId is the AAD TenantID
        /// </summary>
        string TenantId { get; }

        /// <summary>
        /// ClientId is the service principal (application) ID
        /// </summary>
        string ClientId { get; }

        /// <summary>
        /// ClientSecret is the service principal (application) string secret
        /// </summary>
        string ClientSecret { get; }

        /// <summary>
        /// Authority is the URI pointing to the AAD endpoint
        /// </summary>
        string Authority { get; }
    }

    internal class DefaultServicePrincipalConfiguration : IServicePrincipalConfiguration
    {
        public string ClientId => Env.ClientId;

        public string CertificateBase64 => Env.CertificateBase64;

        public string CertificateThumbprint => Env.CertificateThumbprint;

        public string CertificateStoreName => Env.CertificateStoreName;

        public string TenantId => Env.TenantId;

        public string ClientSecret => Env.ClientSecret;

        public string CertificateStoreLocation => Env.CertificateStoreLocation;

        public string CertificateSubjectDistinguishedName => Env.CertificateSubjectDistinguishedName;

        public string Authority => string.IsNullOrWhiteSpace(Env.AadAuthority) ? AadAuthority.DefaultTrustedHost : Env.AadAuthority;
    }

    /// <inheritdoc />
    /// <summary>
    /// ServicePrincipalTokenProvider fetches an AAD token provided Service Principal credentials.
    /// </summary>
    internal class InternalServicePrincipalTokenProvider
    {
        private readonly IConfidentialClientApplication _client;

        internal InternalServicePrincipalTokenProvider(string authority, string tenantId, string clientId, string secret, IMsalHttpClientFactory clientFactory)
        {
            _client = ConfidentialClientApplicationBuilder.Create(clientId)
                .WithTenantId(tenantId)
                .WithAuthority(new Uri(authority))
                .WithClientSecret(secret)
                .WithHttpClientFactory(clientFactory)
                .Build();
        }

        private InternalServicePrincipalTokenProvider(string authority, string tenantId, string clientId, X509Certificate2 cert, IMsalHttpClientFactory clientFactory)
        {
            _client = ConfidentialClientApplicationBuilder.Create(clientId)
                .WithTenantId(tenantId)
                .WithAuthority(new Uri(authority))
                .WithCertificate(cert)
                .WithHttpClientFactory(clientFactory)
                .Build();
        }

        /// <summary>
        ///     ServicePrincipalCredentialProvider constructor to build the provider with a certificate
        /// </summary>
        /// <param name="authority">Hostname of the security token service (STS) from which MSAL.NET will acquire the tokens. Ex: login.microsoftonline.com
        /// </param>
        /// <param name="tenantId">A string representation for a GUID, which is the ID of the tenant where the account resides</param>
        /// <param name="clientId">A string representation for a GUID ClientId (application ID) of the application</param>
        /// <param name="cert">A ClientAssertionCertificate which is the certificate secret for the application</param>
        public InternalServicePrincipalTokenProvider(string authority, string tenantId, string clientId, X509Certificate2 cert)
            : this(authority, tenantId, clientId, cert, null)
        { }

        /// <summary>
        ///     ServicePrincipalCredentialProvider constructor to build the provider with a string secret
        /// </summary>
        /// <param name="authority">Hostname of the security token service (STS) from which MSAL.NET will acquire the tokens. Ex: login.microsoftonline.com
        /// </param>
        /// <param name="tenantId">A string representation for a GUID, which is the ID of the tenant where the account resides</param>
        /// <param name="clientId">A string representation for a GUID ClientId (application ID) of the application</param>
        /// <param name="secret">A string secret for the application</param>
        public InternalServicePrincipalTokenProvider(string authority, string tenantId, string clientId, string secret)
            : this(authority, tenantId, clientId, secret, null)
        { }

        /// <summary>
        ///     GetTokenAsync returns a token for a given set of scopes
        /// </summary>
        /// <param name="scopes">Scopes requested to access a protected API</param>
        /// <returns>A token with expiration</returns>
        public async Task<IToken> GetTokenAsync(IEnumerable<string> scopes = null)
        {
            var res = await _client.AcquireTokenForClientAsync(scopes).ConfigureAwait(false);
            return new AccessTokenWithExpiration { ExpiresOn = res.ExpiresOn, AccessToken = res.AccessToken };
        }
    }

    internal static class AadAuthority
    {
        public const string DefaultTrustedHost = "login.microsoftonline.com";
        public const string AadCanonicalAuthorityTemplate = "https://{0}/{1}/";
    }
}
