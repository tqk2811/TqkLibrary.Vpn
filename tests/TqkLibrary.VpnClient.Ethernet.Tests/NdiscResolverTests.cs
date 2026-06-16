using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Ethernet;
using TqkLibrary.VpnClient.Ethernet.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Ethernet.Tests
{
    public class NdiscResolverTests
    {
        static readonly MacAddress MacA = MacAddress.Parse("02:00:00:00:00:0a");
        static readonly MacAddress MacB = MacAddress.Parse("02:00:00:00:00:0b");
        static readonly MacAddress MacR = MacAddress.Parse("02:00:00:00:00:01");
        static readonly IPAddress IpA = IPAddress.Parse("fe80::a");
        static readonly IPAddress IpB = IPAddress.Parse("fe80::b");
        static readonly IPAddress IpRouter = IPAddress.Parse("fe80::1");

        // ---- Codec: solicited-node multicast + MAC mapping ----

        [Fact]
        public void SolicitedNodeMulticast_TakesLow24Bits()
        {
            IPAddress target = IPAddress.Parse("2001:db8::dead:beef");
            IPAddress solicited = Icmpv6Ndisc.SolicitedNodeMulticast(target);
            Assert.Equal(IPAddress.Parse("ff02::1:ffad:beef"), solicited);   // ff02::1:ff + low 24 bits (ad:beef)
        }

        [Fact]
        public void MulticastMac_Maps3333PlusLast4Bytes()
        {
            IPAddress solicited = IPAddress.Parse("ff02::1:ffad:beef");
            MacAddress mac = Icmpv6Ndisc.MulticastMac(solicited);
            Assert.Equal(MacAddress.Parse("33:33:ff:ad:be:ef"), mac);   // RFC 2464 §7
            Assert.True(mac.IsIpv6Multicast);
        }

        [Fact]
        public void Codec_NeighborSolicitation_RoundTrips_WithChecksum()
        {
            IPAddress dst = Icmpv6Ndisc.SolicitedNodeMulticast(IpB);
            byte[] ns = Icmpv6Ndisc.BuildNeighborSolicitation(IpA, dst, IpB, MacA);

            Assert.Equal(Icmpv6Ndisc.TypeNeighborSolicitation, Icmpv6Ndisc.Type(ns));
            Assert.True(Icmpv6Ndisc.IsNdisc(ns));
            Assert.Equal(IpB, Icmpv6Ndisc.TargetAddress(ns));
            Assert.True(Icmpv6Ndisc.VerifyChecksum(ns, IpA, dst));
            int opt = Icmpv6Ndisc.OptionsOffsetFor(Icmpv6Ndisc.TypeNeighborSolicitation);
            Assert.True(Icmpv6Ndisc.TryGetLinkLayerAddress(ns, opt, Icmpv6Ndisc.OptionSourceLinkLayerAddress, out MacAddress src));
            Assert.Equal(MacA, src);
        }

        [Fact]
        public void Codec_DadSolicitation_OmitsSourceOption()
        {
            // From the unspecified address (DAD), the Source Link-Layer Address option must be absent (RFC 4861 §4.3).
            byte[] ns = Icmpv6Ndisc.BuildNeighborSolicitation(Icmpv6Ndisc.Unspecified, Icmpv6Ndisc.SolicitedNodeMulticast(IpB), IpB, MacA);
            int opt = Icmpv6Ndisc.OptionsOffsetFor(Icmpv6Ndisc.TypeNeighborSolicitation);
            Assert.False(Icmpv6Ndisc.TryGetLinkLayerAddress(ns, opt, Icmpv6Ndisc.OptionSourceLinkLayerAddress, out _));
        }

        // ---- Egress (resolve) ----

        [Fact]
        public async Task Resolve_SendsSolicitation_ThenAdvertisementCompletes()
        {
            var port = new CaptureEthernetChannel();
            await using var ndisc = new NdiscResolver(MacA, IpA, port);

            ValueTask<ReadOnlyMemory<byte>?> pending = ndisc.ResolveAsync(IpB);   // multicasts an NS, then awaits

            byte[] solicit = Assert.Single(port.Written);
            Assert.Equal(EthernetFrame.EtherTypeIpv6, EthernetFrame.EtherType(solicit));
            Assert.Equal(Icmpv6Ndisc.MulticastMac(Icmpv6Ndisc.SolicitedNodeMulticast(IpB)), EthernetFrame.Destination(solicit));
            byte[] ns = Ndisc(solicit);
            Assert.Equal(Icmpv6Ndisc.TypeNeighborSolicitation, Icmpv6Ndisc.Type(ns));
            Assert.Equal(IpB, Icmpv6Ndisc.TargetAddress(ns));

            // The peer answers: ipB is at MacB.
            ndisc.HandleInboundFrame(NaFrame(MacA, MacB, IpB, IpA, IpB, MacB));

            ReadOnlyMemory<byte>? mac = await pending;
            Assert.NotNull(mac);
            Assert.Equal(MacB, MacAddress.FromBytes(mac!.Value.Span));
        }

        [Fact]
        public async Task Resolve_Ipv4_ReturnsNull_WithoutSending()
        {
            var port = new CaptureEthernetChannel();
            await using var ndisc = new NdiscResolver(MacA, IpA, port);

            ReadOnlyMemory<byte>? mac = await ndisc.ResolveAsync(IPAddress.Parse("10.0.0.2"));   // NDISC is IPv6-only

            Assert.Null(mac);
            Assert.Empty(port.Written);
        }

        [Fact]
        public async Task Resolve_Unresolved_TimesOut_ReturnsNull()
        {
            var port = new CaptureEthernetChannel();   // nobody answers
            var options = new NdiscResolverOptions(requestTimeout: TimeSpan.FromMilliseconds(30), maxAttempts: 2);
            await using var ndisc = new NdiscResolver(MacA, IpA, port, options);

            ReadOnlyMemory<byte>? mac = await ndisc.ResolveAsync(IpB);

            Assert.Null(mac);
            Assert.NotEmpty(port.Written);   // at least one NS went out
        }

        [Fact]
        public async Task Resolve_CacheHit_NoSecondSolicitation()
        {
            var port = new CaptureEthernetChannel();
            await using var ndisc = new NdiscResolver(MacA, IpA, port);

            ValueTask<ReadOnlyMemory<byte>?> first = ndisc.ResolveAsync(IpB);
            ndisc.HandleInboundFrame(NaFrame(MacA, MacB, IpB, IpA, IpB, MacB));
            await first;
            Assert.Single(port.Written);

            ReadOnlyMemory<byte>? mac = await ndisc.ResolveAsync(IpB);   // served from cache
            Assert.Equal(MacB, MacAddress.FromBytes(mac!.Value.Span));
            Assert.Single(port.Written);   // no re-solicit
        }

        // ---- Ingress (inbound NS for our address) ----

        [Fact]
        public async Task Inbound_SolicitationForOurAddress_SendsAdvertisement_AndLearnsSender()
        {
            var port = new CaptureEthernetChannel();
            await using var ndisc = new NdiscResolver(MacA, IpA, port);

            // B solicits: who has ipA? (carries B's Source LLA option)
            ndisc.HandleInboundFrame(NsFrame(MacA, MacB, IpB, IpA, sourceMac: MacB));

            byte[] reply = Assert.Single(port.Written);
            Assert.Equal(MacB, EthernetFrame.Destination(reply));   // unicast straight back to the asker
            Assert.Equal(MacA, EthernetFrame.Source(reply));
            byte[] na = Ndisc(reply);
            Assert.Equal(Icmpv6Ndisc.TypeNeighborAdvertisement, Icmpv6Ndisc.Type(na));
            Assert.Equal(IpA, Icmpv6Ndisc.TargetAddress(na));
            Assert.True((Icmpv6Ndisc.NaFlags(na) & Icmpv6Ndisc.FlagSolicited) != 0);
            int opt = Icmpv6Ndisc.OptionsOffsetFor(Icmpv6Ndisc.TypeNeighborAdvertisement);
            Assert.True(Icmpv6Ndisc.TryGetLinkLayerAddress(na, opt, Icmpv6Ndisc.OptionTargetLinkLayerAddress, out MacAddress targetMac));
            Assert.Equal(MacA, targetMac);

            // The solicitation also taught us ipB→MacB.
            ReadOnlyMemory<byte>? mac = await ndisc.ResolveAsync(IpB);
            Assert.Equal(MacB, MacAddress.FromBytes(mac!.Value.Span));
            Assert.Single(port.Written);   // resolved from passive learning, no new NS
        }

        [Fact]
        public async Task Inbound_SolicitationForOtherAddress_NoReply()
        {
            var port = new CaptureEthernetChannel();
            await using var ndisc = new NdiscResolver(MacA, IpA, port);

            // B solicits ipRouter (not us) — we stay silent but still learn B.
            ndisc.HandleInboundFrame(NsFrame(MacA, MacB, IpB, IpRouter, sourceMac: MacB));
            Assert.Empty(port.Written);

            ReadOnlyMemory<byte>? mac = await ndisc.ResolveAsync(IpB);
            Assert.Equal(MacB, MacAddress.FromBytes(mac!.Value.Span));
            Assert.Empty(port.Written);
        }

        // ---- Router Advertisement parse ----

        [Fact]
        public void Inbound_RouterAdvertisement_ParsesGatewayAndPrefix()
        {
            var port = new CaptureEthernetChannel();
            var ndisc = new NdiscResolver(MacA, IpA, port);
            RouterAdvertisementInfo? raised = null;
            ndisc.RouterAdvertisementReceived += info => raised = info;

            byte prefixFlags = (byte)(Icmpv6Ndisc.PrefixFlagOnLink | Icmpv6Ndisc.PrefixFlagAutonomous);
            byte[] ra = Icmpv6Ndisc.BuildRouterAdvertisement(IpRouter, Icmpv6Ndisc.AllNodes, MacR,
                curHopLimit: 64, routerLifetimeSeconds: 1800,
                prefix: IPAddress.Parse("2001:db8:1234::"), prefixLength: 64, prefixFlags: prefixFlags,
                validLifetime: 86400, preferredLifetime: 14400);
            byte[] ipv6 = Icmpv6Ndisc.BuildIpv6(IpRouter, Icmpv6Ndisc.AllNodes, ra);
            byte[] frame = EthernetFrame.Build(Icmpv6Ndisc.MulticastMac(Icmpv6Ndisc.AllNodes), MacR, EthernetFrame.EtherTypeIpv6, ipv6);

            ndisc.HandleInboundFrame(frame);

            RouterAdvertisementInfo info = ndisc.LastRouterAdvertisement!;
            Assert.NotNull(info);
            Assert.Same(info, raised);
            Assert.Equal(IpRouter, info.Router);                 // gateway = RA source
            Assert.Equal(MacR, info.RouterMac);                  // from Source LLA option
            Assert.Equal((ushort)1800, info.RouterLifetimeSeconds);
            Assert.Equal(IPAddress.Parse("2001:db8:1234::"), info.Prefix);
            Assert.Equal((byte)64, info.PrefixLength);
            Assert.True(info.PrefixOnLink);
            Assert.True(info.PrefixAutonomous);
            Assert.Equal(86400u, info.PrefixValidLifetime);
            Assert.Equal(14400u, info.PrefixPreferredLifetime);
        }

        // ---- DAD ----

        [Fact]
        public async Task Dad_UniqueAddress_PassesWhenSilent()
        {
            var port = new CaptureEthernetChannel();
            var options = new NdiscResolverOptions(dadTimeout: TimeSpan.FromMilliseconds(40));
            await using var ndisc = new NdiscResolver(MacA, IpA, port, options);

            bool unique = await ndisc.PerformDuplicateAddressDetectionAsync();

            Assert.True(unique);   // nobody defended
            byte[] probe = Assert.Single(port.Written);
            byte[] ns = Ndisc(probe);
            Assert.Equal(Icmpv6Ndisc.TypeNeighborSolicitation, Icmpv6Ndisc.Type(ns));
            Assert.Equal(IpA, Icmpv6Ndisc.TargetAddress(ns));
            // DAD probe source is the unspecified address (::), so it has no Source LLA option.
            int opt = Icmpv6Ndisc.OptionsOffsetFor(Icmpv6Ndisc.TypeNeighborSolicitation);
            Assert.False(Icmpv6Ndisc.TryGetLinkLayerAddress(ns, opt, Icmpv6Ndisc.OptionSourceLinkLayerAddress, out _));
        }

        [Fact]
        public async Task Dad_DuplicateAddress_DetectedByDefendingAdvertisement()
        {
            var port = new CaptureEthernetChannel();
            var options = new NdiscResolverOptions(dadTimeout: TimeSpan.FromSeconds(5));
            await using var ndisc = new NdiscResolver(MacA, IpA, port, options);

            Task<bool> dad = ndisc.PerformDuplicateAddressDetectionAsync();

            // Another host already owns ipA and defends it with an NA.
            ndisc.HandleInboundFrame(NaFrame(MacAddress.Broadcast, MacB, IpA, Icmpv6Ndisc.AllNodes, IpA, MacB));

            bool unique = await dad;
            Assert.False(unique);   // duplicate detected
        }

        // ---- Integration: real NDISC exchange between two hosts over the switch ----

        [Fact]
        public async Task Integration_TwoHostsNdiscOverSwitch_DeliversIpPacket()
        {
            await using var sw = new EthernetSwitch();
            IEthernetChannel portA = sw.ConnectHost(MacA);
            IEthernetChannel portB = sw.ConnectHost(MacB);
            await using var ndiscA = new NdiscResolver(MacA, IpA, portA);
            await using var ndiscB = new NdiscResolver(MacB, IpB, portB);
            await using var hostA = new VirtualHost(MacA, portA, ndiscA);
            await using var hostB = new VirtualHost(MacB, portB, ndiscB);
            // NDISC rides inside IPv6, so it sees BOTH the non-IP seam and the inbound IP packets.
            hostA.InboundIpPacket += ndiscA.HandleInboundFrame;
            hostB.InboundIpPacket += ndiscB.HandleInboundFrame;
            byte[]? bGot = null;
            hostB.InboundIpPacket += p => { if (!IsNdiscPacket(p)) bGot = p.ToArray(); };

            byte[] ip = Ipv6Packet(IpA, IpB, 1, 2, 3);
            await hostA.WriteIpPacketAsync(ip);   // egress A → NDISC resolves ipB via real NS/NA → wrap → B

            Assert.NotNull(bGot);
            Assert.Equal(ip, bGot);
        }

        // ---- Helpers ----

        /// <summary>Extracts the ICMPv6 NDISC message from a captured Ethernet/IPv6 frame.</summary>
        static byte[] Ndisc(byte[] frame)
        {
            byte[] ipv6 = EthernetFrame.Payload(frame).ToArray();
            return new ReadOnlySpan<byte>(ipv6, 40, ipv6.Length - 40).ToArray();
        }

        static bool IsNdiscPacket(ReadOnlyMemory<byte> ipv6)
        {
            ReadOnlySpan<byte> p = ipv6.Span;
            return p.Length >= 48 && (byte)(p[0] >> 4) == 6 && p[6] == Icmpv6Ndisc.ProtocolNumber
                   && Icmpv6Ndisc.IsNdisc(p.Slice(40));
        }

        static byte[] NaFrame(MacAddress dstMac, MacAddress srcMac, IPAddress src, IPAddress dst, IPAddress target, MacAddress targetMac)
        {
            byte flags = (byte)(Icmpv6Ndisc.FlagSolicited | Icmpv6Ndisc.FlagOverride);
            byte[] na = Icmpv6Ndisc.BuildNeighborAdvertisement(src, dst, target, targetMac, flags);
            byte[] ipv6 = Icmpv6Ndisc.BuildIpv6(src, dst, na);
            return EthernetFrame.Build(dstMac, srcMac, EthernetFrame.EtherTypeIpv6, ipv6);
        }

        static byte[] NsFrame(MacAddress dstMac, MacAddress srcMac, IPAddress src, IPAddress target, MacAddress sourceMac)
        {
            byte[] ns = Icmpv6Ndisc.BuildNeighborSolicitation(src, Icmpv6Ndisc.SolicitedNodeMulticast(target), target, sourceMac);
            byte[] ipv6 = Icmpv6Ndisc.BuildIpv6(src, Icmpv6Ndisc.SolicitedNodeMulticast(target), ns);
            return EthernetFrame.Build(dstMac, srcMac, EthernetFrame.EtherTypeIpv6, ipv6);
        }

        /// <summary>A minimal IPv6 packet: version nibble 6, src @ offset 8, dst @ offset 24 (RFC 8200), then payload.</summary>
        static byte[] Ipv6Packet(IPAddress source, IPAddress destination, params byte[] payload)
        {
            byte[] packet = new byte[40 + payload.Length];
            packet[0] = 0x60;   // version 6
            packet[4] = (byte)(payload.Length >> 8);
            packet[5] = (byte)payload.Length;
            packet[6] = 17;     // next header = UDP (anything that is NOT 58/ICMPv6 so it is not mistaken for NDISC)
            packet[7] = 64;
            source.GetAddressBytes().CopyTo(packet, 8);
            destination.GetAddressBytes().CopyTo(packet, 24);
            payload.CopyTo(packet, 40);
            return packet;
        }

        /// <summary>An <see cref="IEthernetChannel"/> that records frames written out and lets the test raise inbound frames.</summary>
        sealed class CaptureEthernetChannel : IEthernetChannel
        {
            public List<byte[]> Written { get; } = new();
            public int Mtu { get; set; } = 1500;
            public LinkMedium Medium => LinkMedium.Ethernet;
            public int MaxHeaderLength => EthernetFrame.HeaderLength;
            public bool RequiresLinkAddressResolution => true;
            public ReadOnlyMemory<byte> LinkAddress { get; set; }
            public bool Disposed { get; private set; }
            public event Action<ReadOnlyMemory<byte>>? InboundFrame;

            public ValueTask WriteFrameAsync(ReadOnlyMemory<byte> ethernetFrame, CancellationToken cancellationToken = default)
            {
                Written.Add(ethernetFrame.ToArray());
                return default;
            }

            public void RaiseInbound(ReadOnlyMemory<byte> frame) => InboundFrame?.Invoke(frame);

            public ValueTask DisposeAsync()
            {
                Disposed = true;
                InboundFrame = null;
                return default;
            }
        }
    }
}
