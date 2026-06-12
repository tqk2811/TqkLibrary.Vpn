using System;

namespace TqkLibrary.Vpn.Ethernet
{
    /// <summary>
    /// Tunables for <see cref="ArpResolver"/>: how long a learned IP→MAC entry is trusted, and how patiently an
    /// unresolved address is retried before <see cref="ArpResolver.ResolveAsync"/> gives up. Tests use much shorter
    /// timeouts so the time-out path runs fast and a zero TTL so the cache is bypassed deterministically.
    /// </summary>
    /// <remarks>
    /// Plain class (no <c>record</c>/<c>init</c>) so it compiles on <c>netstandard2.0</c>; all values are
    /// constructor-set and read-only, so <see cref="Default"/> is safe to share.
    /// </remarks>
    public sealed class ArpResolverOptions
    {
        /// <summary>How long a learned IP→MAC entry stays valid before the next resolve re-ARPs for it.</summary>
        public TimeSpan CacheTtl { get; }

        /// <summary>How long to wait for a reply after sending one ARP request before retrying or giving up.</summary>
        public TimeSpan RequestTimeout { get; }

        /// <summary>Number of ARP requests sent before a resolve gives up and returns <c>null</c>.</summary>
        public int MaxAttempts { get; }

        /// <summary>Creates the options; any timing argument left <c>null</c> takes its default.</summary>
        public ArpResolverOptions(TimeSpan? cacheTtl = null, TimeSpan? requestTimeout = null, int maxAttempts = 3)
        {
            CacheTtl = cacheTtl ?? TimeSpan.FromSeconds(20);
            RequestTimeout = requestTimeout ?? TimeSpan.FromSeconds(1);
            MaxAttempts = maxAttempts < 1 ? 1 : maxAttempts;
        }

        /// <summary>Defaults used when no options are supplied (20s TTL, 1s request timeout, 3 attempts).</summary>
        public static ArpResolverOptions Default { get; } = new ArpResolverOptions();
    }
}
