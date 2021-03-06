﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Identity.Client.Extensions.Msal.UnitTests
{
    [TestClass]
    public class MsalCacheHelperTests
    {
        public static readonly string CacheFilePath = Path.Combine(Path.GetTempPath(), Path.GetTempFileName());
        private readonly TraceSource _logger = new TraceSource("TestSource");
        private static StorageCreationProperties s_storageCreationProperties;

        [ClassInitialize]
        public static void ClassInitialize(TestContext _)
        {
            var builder = new StorageCreationPropertiesBuilder(Path.GetFileName(CacheFilePath), Path.GetDirectoryName(CacheFilePath), "ClientIDGoesHere");
            builder = builder.WithMacKeyChain(serviceName: "Microsoft.Developer.IdentityService", accountName: "MSALCache");
            builder = builder.WithLinuxKeyring(
                schemaName: "msal.cache",
                collection: "default",
                secretLabel: "MSALCache",
                attribute1: new KeyValuePair<string, string>("MsalClientID", "Microsoft.Developer.IdentityService"),
                attribute2: new KeyValuePair<string, string>("MsalClientVersion", "1.0.0.0"));
            s_storageCreationProperties = builder.Build();
        }

        [TestMethod]
        public void MultiAccessSerializationAsync()
        {
            var cache1 = new MockTokenCache();
            var helper1 = new MsalCacheHelper(
                cache1,
                new MsalCacheStorage(s_storageCreationProperties, _logger),
                _logger);

            var cache2 = new MockTokenCache();
            var helper2 = new MsalCacheHelper(
                cache2,
                new MsalCacheStorage(s_storageCreationProperties, _logger),
                _logger);

            //Test signalling thread 1
            var resetEvent1 = new ManualResetEvent(initialState: false);

            //Test signalling thread 2
            var resetEvent2 = new ManualResetEvent(initialState: false);

            //Thread 1 signalling test
            var resetEvent3 = new ManualResetEvent(initialState: false);

            // Thread 2 signalling test
            var resetEvent4 = new ManualResetEvent(initialState: false);

            var thread1 = new Thread(() =>
            {
                var args = new TokenCacheNotificationArgs
                {
                    TokenCache = cache1
                };

                helper1.BeforeAccessNotification(args);
                resetEvent3.Set();
                resetEvent1.WaitOne();
                helper1.AfterAccessNotification(args);
            });

            var thread2 = new Thread(() =>
            {
                var args = new TokenCacheNotificationArgs
                {
                    TokenCache = cache2
                };

                helper2.BeforeAccessNotification(args);
                resetEvent4.Set();
                resetEvent2.WaitOne();
                helper2.AfterAccessNotification(args);
                resetEvent4.Set();
            });

            // Let thread 1 start and get the lock
            thread1.Start();
            resetEvent3.WaitOne();

            // Start thread 2 and give it enough time to get blocked on the lock
            thread2.Start();
            Thread.Sleep(5000);

            // Make sure helper1 has the lock still, and helper2 doesn't
            Assert.IsNotNull(helper1.CacheLock);
            Assert.IsNull(helper2.CacheLock);

            // Allow thread1 to give up the lock, and wait for helper2 to get it
            resetEvent1.Set();
            resetEvent4.WaitOne();
            resetEvent4.Reset();

            // Make sure helper1 gave it up properly, and helper2 now owns the lock
            Assert.IsNull(helper1.CacheLock);
            Assert.IsNotNull(helper2.CacheLock);

            // Allow thread2 to give up the lock, and wait for it to complete
            resetEvent2.Set();
            resetEvent4.WaitOne();

            // Make sure thread2 cleaned up after itself as well
            Assert.IsNull(helper2.CacheLock);
        }

        [TestMethod]
        public async Task TwoRegisteredCachesRemainInSyncTestAsync()
        {
            if (File.Exists(s_storageCreationProperties.CacheFilePath))
            {
                File.Delete(s_storageCreationProperties.CacheFilePath);
            }

            var helper = await MsalCacheHelper.CreateAsync(s_storageCreationProperties).ConfigureAwait(true);
            helper._cacheWatcher.EnableRaisingEvents = false;

            // Intentionally write the file after creating the MsalCacheHelper to avoid the initial inner PCA being created only to read garbage
            string startString = "Something to start with";
            var startBytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(startString), optionalEntropy: null, scope: DataProtectionScope.CurrentUser);
            await File.WriteAllBytesAsync(s_storageCreationProperties.CacheFilePath, startBytes).ConfigureAwait(true);

            var cache1 = new MockTokenCache();
            var cache2 = new MockTokenCache();

            helper.RegisterCache(cache1);
            helper.RegisterCache(cache2);

            // One call from register
            Assert.AreEqual(1, cache1.DeserializeMsalV3_MergeCache);
            Assert.AreEqual(1, cache2.DeserializeMsalV3_MergeCache);
            Assert.AreEqual(startString, cache1.LastDeserializedString);
            Assert.AreEqual(startString, cache2.LastDeserializedString);

            var args1 = new TokenCacheNotificationArgs
            {
                TokenCache = cache1
            };

            var args2 = new TokenCacheNotificationArgs
            {
                TokenCache = cache2
            };

            File.Delete(s_storageCreationProperties.CacheFilePath);
            var changedString = "Hey look, the file changed";
            var changedBytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(changedString), optionalEntropy: null, scope: DataProtectionScope.CurrentUser);
            await File.WriteAllBytesAsync(s_storageCreationProperties.CacheFilePath, changedBytes).ConfigureAwait(true);

            helper.BeforeAccessNotification(args1);
            helper.AfterAccessNotification(args1);

            helper.BeforeAccessNotification(args2);
            helper.AfterAccessNotification(args2);

            // Still only one call from register
            Assert.AreEqual(1, cache1.DeserializeMsalV3_MergeCache);
            Assert.AreEqual(1, cache2.DeserializeMsalV3_MergeCache);

            // One call from BeforeAccess
            Assert.AreEqual(1, cache1.DeserializeMsalV3_ClearCache);
            Assert.AreEqual(1, cache2.DeserializeMsalV3_ClearCache);

            Assert.AreEqual(changedString, cache1.LastDeserializedString);
            Assert.AreEqual(changedString, cache2.LastDeserializedString);

            File.Delete(s_storageCreationProperties.CacheFilePath);
        }
    }
}
