using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Ethernet;
using TqkLibrary.VpnClient.Ppp.Ipv6;
using Xunit;

namespace TqkLibrary.VpnClient.Ppp.Tests
{
    /// <summary>
    /// Offline tests for <see cref="PppIpv6Autoconfigurator"/> (P1.1): global IPv6 over a PPP link. A fake L3 channel
    /// stands in for the PPP <see cref="IPacketChannel"/>; a "server" answers the Router Solicitation with a Router
    /// Advertisement carrying an autonomous /64 prefix, and the autoconfigurator must form the global address from that
    /// prefix and the IPV6CP interface identifier (the low 64 bits of the link-local), not a synthetic MAC's EUI-64.
    /// </summary>
    public class PppIpv6AutoconfiguratorTests
    {
        static readonly IPAddress LinkLocal = IPAddress.Parse("fe80::200:0:0:42");   // fe80::/64 + IID 02:00:..:42
        static readonly byte[] InterfaceId = { 0x02, 0, 0, 0, 0, 0, 0, 0x42 };        // the low 64 bits of LinkLocal
        static readonly IPAddress Prefix = IPAddress.Parse("2001:db8:1:2::");          // an autonomous /64
        static readonly IPAddress RouterLla = IPAddress.Parse("fe80::1");
        static readonly MacAddress RouterMac = MacAddress.Parse("00:11:22:33:44:55");

        [Fact]
        public async Task SolicitsRouterAdvertisement_FormsGlobalAddressFromPrefixAndIpv6cpIdentifier()
        {
            // The server replies to a Router Solicitation with an RA carrying an autonomous /64 prefix.
            var channel = new RaServerChannel(respondWithRa: true);
            var autoconfig = new PppIpv6Autoconfigurator(routerAdvertisementTimeout: TimeSpan.FromMilliseconds(500));

            TunnelConfig? config = await autoconfig.TryConfigureAsync(channel, LinkLocal, InterfaceId);

            Assert.NotNull(config);
            // global = the advertised /64 prefix (high 64 bits) ‖ the IPV6CP interface identifier (low 64 bits)
            byte[] expected = new byte[16];
            Array.Copy(Prefix.GetAddressBytes(), 0, expected, 0, 8);
            Array.Copy(InterfaceId, 0, expected, 8, 8);
            Assert.Equal(new IPAddress(expected), config!.AssignedAddressV6);
            Assert.Equal(64, config.PrefixLengthV6);
            Assert.Contains($"::/0 {RouterLla}", config.Routes);                       // the advertising router is the v6 gateway
            Assert.True(channel.SawRouterSolicitation);                                // we really solicited it
        }

        [Fact]
        public async Task NoRouterAnswers_ReturnsNull_BestEffortKeepsLinkLocal()
        {
            var channel = new RaServerChannel(respondWithRa: false);
            var autoconfig = new PppIpv6Autoconfigurator(routerAdvertisementTimeout: TimeSpan.FromMilliseconds(30), routerSolicitationAttempts: 2);

            TunnelConfig? config = await autoconfig.TryConfigureAsync(channel, LinkLocal, InterfaceId);

            Assert.Null(config);
            Assert.True(channel.SawRouterSolicitation);
        }

        [Fact]
        public async Task RejectsBadInput_ReturnsNull()
        {
            var channel = new RaServerChannel(respondWithRa: true);
            var autoconfig = new PppIpv6Autoconfigurator();

            Assert.Null(await autoconfig.TryConfigureAsync(channel, IPAddress.Parse("10.0.0.1"), InterfaceId)); // not IPv6
            Assert.Null(await autoconfig.TryConfigureAsync(channel, LinkLocal, new byte[7]));                    // IID not 8 bytes
        }

        /// <summary>
        /// A minimal L3 channel: it watches each sent packet for a Router Solicitation (ICMPv6 type 133) and, if asked,
        /// answers inline with a Router Advertisement (raised back on <see cref="InboundIpPacket"/>) carrying an
        /// autonomous /64 prefix.
        /// </summary>
        sealed class RaServerChannel : IPacketChannel
        {
            const byte Icmpv6 = 58;
            const byte RouterSolicitation = 133;
            readonly bool _respondWithRa;

            public RaServerChannel(bool respondWithRa) => _respondWithRa = respondWithRa;

            public bool SawRouterSolicitation { get; private set; }

            public LinkMedium Medium => LinkMedium.Ip;
            public int Mtu => 1400;
            public int MaxHeaderLength => 0;
            public bool RequiresLinkAddressResolution => false;
            public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

            public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
            {
                ReadOnlySpan<byte> p = ipPacket.Span;
                bool isRs = p.Length >= 41 && (byte)(p[0] >> 4) == 6 && p[6] == Icmpv6 && p[40] == RouterSolicitation;
                if (isRs)
                {
                    SawRouterSolicitation = true;
                    if (_respondWithRa)
                        InboundIpPacket?.Invoke(BuildRouterAdvertisement());
                }
                return default;
            }

            public ValueTask DisposeAsync() => default;

            static byte[] BuildRouterAdvertisement()
            {
                byte prefixFlags = (byte)(Icmpv6Ndisc.PrefixFlagOnLink | Icmpv6Ndisc.PrefixFlagAutonomous);
                byte[] ra = Icmpv6Ndisc.BuildRouterAdvertisement(RouterLla, LinkLocal, RouterMac,
                    curHopLimit: 64, routerLifetimeSeconds: 1800,
                    prefix: Prefix, prefixLength: 64, prefixFlags: prefixFlags,
                    validLifetime: 86400, preferredLifetime: 14400);
                return Icmpv6Ndisc.BuildIpv6(RouterLla, LinkLocal, ra);
            }
        }
    }
}
