using System;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// Tunables for <see cref="NdiscResolver"/>: how long a learned IPv6→MAC neighbor-cache entry is trusted, how
    /// patiently an unresolved address is retried before <see cref="NdiscResolver.ResolveAsync"/> gives up, and how long
    /// Duplicate Address Detection waits for a defending Neighbor Advertisement. The NDISC counterpart of
    /// <see cref="ArpResolverOptions"/>; tests use much shorter timeouts so the time-out and DAD paths run fast and a
    /// zero TTL so the cache is bypassed deterministically.
    /// </summary>
    /// <remarks>
    /// Plain class (no <c>record</c>/<c>init</c>) so it compiles on <c>netstandard2.0</c>; all values are
    /// constructor-set and read-only, so <see cref="Default"/> is safe to share.
    /// </remarks>
    public sealed class NdiscResolverOptions
    {
        /// <summary>How long a learned IPv6→MAC neighbor entry stays valid before the next resolve re-solicits for it.</summary>
        public TimeSpan CacheTtl { get; }

        /// <summary>How long to wait for a reply after sending one Neighbor Solicitation before retrying or giving up.</summary>
        public TimeSpan RequestTimeout { get; }

        /// <summary>Number of Neighbor Solicitations sent before a resolve gives up and returns <c>null</c>.</summary>
        public int MaxAttempts { get; }

        /// <summary>How long Duplicate Address Detection waits for a defending Neighbor Advertisement (RFC 4862 §5.4).</summary>
        public TimeSpan DadTimeout { get; }

        /// <summary>Number of DAD Neighbor Solicitations sent (RFC 4862 default DupAddrDetectTransmits = 1).</summary>
        public int DadTransmits { get; }

        /// <summary>Creates the options; any timing argument left <c>null</c> takes its default.</summary>
        public NdiscResolverOptions(TimeSpan? cacheTtl = null, TimeSpan? requestTimeout = null, int maxAttempts = 3, TimeSpan? dadTimeout = null, int dadTransmits = 1)
        {
            CacheTtl = cacheTtl ?? TimeSpan.FromSeconds(20);
            RequestTimeout = requestTimeout ?? TimeSpan.FromSeconds(1);
            MaxAttempts = maxAttempts < 1 ? 1 : maxAttempts;
            DadTimeout = dadTimeout ?? TimeSpan.FromSeconds(1);
            DadTransmits = dadTransmits < 1 ? 1 : dadTransmits;
        }

        /// <summary>Defaults used when no options are supplied (20s TTL, 1s request timeout, 3 attempts, 1s/1× DAD).</summary>
        public static NdiscResolverOptions Default { get; } = new NdiscResolverOptions();
    }
}
