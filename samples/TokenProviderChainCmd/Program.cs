using System;
using Microsoft.Identity.Extensions.Msal.Providers;

namespace TokenProviderChainCmd
{
    class Program
    {
        static void Main(string[] args)
        {
            var chain = new DefaultTokenProviderChain();
            var available = chain.AvailableAsync().ConfigureAwait(false).GetAwaiter().GetResult();
            Console.Out.WriteLine(available ? "Available!" : "Not Available!");
        }
    }
}
