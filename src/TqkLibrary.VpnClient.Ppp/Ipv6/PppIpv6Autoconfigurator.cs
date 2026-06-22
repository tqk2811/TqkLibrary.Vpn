using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Ethernet;

namespace TqkLibrary.VpnClient.Ppp.Ipv6
{
    /// <summary>
    /// Default <see cref="IPppIpv6Autoconfigurator"/>: reuses the L3 IPv6 auto-configuration engine
    /// (<see cref="NdiscResolver"/> + <see cref="Ipv6AddressConfigurator"/>) over a PPP link via
    /// <see cref="PppEthernetChannelAdapter"/>. SLAAC forms the global address from the advertised prefix and the IPV6CP
    /// interface identifier (passed through <see cref="Ipv6AddressConfiguratorOptions.InterfaceIdentifierOverride"/> so the
    /// global address shares the link's identifier rather than a synthetic MAC's EUI-64); DHCPv6 rides the same adapter.
    /// Timeouts are short because this sits on the connect path and is purely best-effort.
    /// </summary>
    public sealed class PppIpv6Autoconfigurator : IPppIpv6Autoconfigurator
    {
        readonly TimeSpan _routerAdvertisementTimeout;
        readonly int _routerSolicitationAttempts;
        readonly TimeSpan _dhcpReplyTimeout;
        readonly int _dhcpMaxAttempts;

        /// <summary>
        /// Creates the autoconfigurator. The timeouts sit on the connect path so they default short; a test passes tiny
        /// values to exercise the time-out (no-router) path quickly.
        /// </summary>
        public PppIpv6Autoconfigurator(
            TimeSpan? routerAdvertisementTimeout = null,
            int routerSolicitationAttempts = 2,
            TimeSpan? dhcpReplyTimeout = null,
            int dhcpMaxAttempts = 2)
        {
            _routerAdvertisementTimeout = routerAdvertisementTimeout ?? TimeSpan.FromSeconds(1.5);
            _routerSolicitationAttempts = routerSolicitationAttempts;
            _dhcpReplyTimeout = dhcpReplyTimeout ?? TimeSpan.FromSeconds(1);
            _dhcpMaxAttempts = dhcpMaxAttempts;
        }

        /// <inheritdoc/>
        public async Task<TunnelConfig?> TryConfigureAsync(IPacketChannel channel, IPAddress linkLocal, byte[] interfaceId, CancellationToken cancellationToken = default)
        {
            if (channel is null || linkLocal is null || linkLocal.AddressFamily != AddressFamily.InterNetworkV6 || interfaceId is null || interfaceId.Length != 8)
                return null;

            MacAddress mac = SynthesizeMac(interfaceId);
            var adapter = new PppEthernetChannelAdapter(channel, mac);
            var ndisc = new NdiscResolver(mac, linkLocal, adapter);
            var options = new Ipv6AddressConfiguratorOptions(
                routerAdvertisementTimeout: _routerAdvertisementTimeout,
                routerSolicitationAttempts: _routerSolicitationAttempts,
                dhcpReplyTimeout: _dhcpReplyTimeout,
                dhcpMaxAttempts: _dhcpMaxAttempts,
                interfaceIdentifierOverride: interfaceId);
            var configurator = new Ipv6AddressConfigurator(mac, linkLocal, adapter, ndisc, options);

            // NDISC parses the Router Advertisement; the configurator catches DHCPv6 replies. Wire both before Start() so
            // no inbound packet is missed once the engine begins listening on the channel.
            adapter.InboundFrame += ndisc.HandleInboundFrame;
            adapter.InboundFrame += configurator.HandleInboundFrame;
            adapter.Start();
            try
            {
                return await configurator.ConfigureAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (InvalidOperationException)
            {
                // No Router Advertisement and no DHCPv6 lease, or the channel was disposed mid-exchange
                // (ObjectDisposedException derives from InvalidOperationException) — best-effort, keep the link-local.
                return null;
            }
            finally
            {
                await configurator.DisposeAsync().ConfigureAwait(false);
                await ndisc.DisposeAsync().ConfigureAwait(false);
                await adapter.DisposeAsync().ConfigureAwait(false);
            }
        }

        // A locally-administered unicast MAC (first octet 0x02) derived from the interface identifier — used only for the
        // cosmetic Source Link-Layer Address option / DHCPv6 DUID on a point-to-point link; the SLAAC identifier is the
        // IPV6CP one via InterfaceIdentifierOverride.
        static MacAddress SynthesizeMac(byte[] interfaceId)
        {
            byte[] m = { 0x02, interfaceId[1], interfaceId[2], interfaceId[5], interfaceId[6], interfaceId[7] };
            return MacAddress.FromBytes(m);
        }
    }
}
