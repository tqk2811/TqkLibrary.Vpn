using System;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// Tunables for <see cref="DhcpV4Configurator"/>: how long to wait for an OFFER/ACK before retransmitting the
    /// DISCOVER/REQUEST, how many times to retransmit before giving up, and the MTU to record on the resulting
    /// <see cref="Abstractions.Drivers.Models.TunnelConfig"/>. Tests use short timeouts so the time-out/NAK paths run
    /// fast.
    /// </summary>
    /// <remarks>
    /// Plain class (no <c>record</c>/<c>init</c>) so it compiles on <c>netstandard2.0</c>; all values are
    /// constructor-set and read-only, so <see cref="Default"/> is safe to share.
    /// </remarks>
    public sealed class DhcpV4ConfiguratorOptions
    {
        /// <summary>How long to wait for an OFFER (after DISCOVER) or an ACK (after REQUEST) before retransmitting.</summary>
        public TimeSpan ReplyTimeout { get; }

        /// <summary>Number of DISCOVER (or REQUEST) messages sent before a phase gives up and fails.</summary>
        public int MaxAttempts { get; }

        /// <summary>The MTU recorded on the produced <see cref="Abstractions.Drivers.Models.TunnelConfig"/>.</summary>
        public int Mtu { get; }

        /// <summary>Creates the options; any timing argument left <c>null</c> takes its default.</summary>
        public DhcpV4ConfiguratorOptions(TimeSpan? replyTimeout = null, int maxAttempts = 4, int mtu = 1500)
        {
            ReplyTimeout = replyTimeout ?? TimeSpan.FromSeconds(2);
            MaxAttempts = maxAttempts < 1 ? 1 : maxAttempts;
            Mtu = mtu < 576 ? 576 : mtu;
        }

        /// <summary>Defaults used when no options are supplied (2s reply timeout, 4 attempts, MTU 1500).</summary>
        public static DhcpV4ConfiguratorOptions Default { get; } = new DhcpV4ConfiguratorOptions();
    }
}
