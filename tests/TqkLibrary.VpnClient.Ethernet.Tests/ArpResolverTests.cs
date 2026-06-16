using System;
using System.Collections.Generic;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Ethernet;
using Xunit;

namespace TqkLibrary.VpnClient.Ethernet.Tests
{
    public class ArpResolverTests
    {
        static readonly MacAddress MacA = MacAddress.Parse("02:00:00:00:00:0a");
        static readonly MacAddress MacB = MacAddress.Parse("02:00:00:00:00:0b");
        static readonly IPAddress IpA = IPAddress.Parse("10.0.0.1");
        static readonly IPAddress IpB = IPAddress.Parse("10.0.0.2");
        static readonly IPAddress IpC = IPAddress.Parse("10.0.0.3");

        // ---- Egress (resolve) ----

        [Fact]
        public async Task Resolve_SendsRequest_ThenReplyCompletes()
        {
            var port = new CaptureEthernetChannel();
            await using var arp = new ArpResolver(MacA, IpA, port);

            ValueTask<ReadOnlyMemory<byte>?> pending = arp.ResolveAsync(IpB);   // broadcasts a request, then awaits

            byte[] request = Assert.Single(port.Written);
            Assert.Equal(EthernetFrame.EtherTypeArp, EthernetFrame.EtherType(request));
            Assert.Equal(MacAddress.Broadcast, EthernetFrame.Destination(request));
            Assert.Equal(MacA, EthernetFrame.Source(request));
            byte[] reqArp = EthernetFrame.Payload(request).ToArray();
            Assert.Equal(ArpPacket.OperationRequest, ArpPacket.Operation(reqArp));
            Assert.Equal(IpB, ArpPacket.TargetIp(reqArp));

            // The peer answers: ipB is at MacB.
            arp.HandleInboundFrame(ArpFrame(MacA, MacB, ArpPacket.BuildReply(MacB, IpB, MacA, IpA)));

            ReadOnlyMemory<byte>? mac = await pending;
            Assert.NotNull(mac);
            Assert.Equal(MacB, MacAddress.FromBytes(mac!.Value.Span));
        }

        [Fact]
        public async Task Resolve_Ipv6_ReturnsNull_WithoutSending()
        {
            var port = new CaptureEthernetChannel();
            await using var arp = new ArpResolver(MacA, IpA, port);

            ReadOnlyMemory<byte>? mac = await arp.ResolveAsync(IPAddress.Parse("fd00::2"));   // ARP is IPv4-only

            Assert.Null(mac);
            Assert.Empty(port.Written);
        }

        [Fact]
        public async Task Resolve_Unresolved_TimesOut_ReturnsNull()
        {
            var port = new CaptureEthernetChannel();   // nobody answers
            var options = new ArpResolverOptions(requestTimeout: TimeSpan.FromMilliseconds(30), maxAttempts: 2);
            await using var arp = new ArpResolver(MacA, IpA, port, options);

            ReadOnlyMemory<byte>? mac = await arp.ResolveAsync(IpB);

            Assert.Null(mac);
            Assert.NotEmpty(port.Written);   // at least one ARP request went out
        }

        [Fact]
        public async Task Resolve_CacheHit_NoSecondRequest()
        {
            var port = new CaptureEthernetChannel();
            await using var arp = new ArpResolver(MacA, IpA, port);

            ValueTask<ReadOnlyMemory<byte>?> first = arp.ResolveAsync(IpB);
            arp.HandleInboundFrame(ArpFrame(MacA, MacB, ArpPacket.BuildReply(MacB, IpB, MacA, IpA)));
            await first;
            Assert.Single(port.Written);   // one request for the first resolve

            ReadOnlyMemory<byte>? mac = await arp.ResolveAsync(IpB);   // served from cache
            Assert.Equal(MacB, MacAddress.FromBytes(mac!.Value.Span));
            Assert.Single(port.Written);   // still just the one request — no re-ARP
        }

        // ---- Ingress (inbound ARP) ----

        [Fact]
        public async Task Inbound_RequestForOurIp_SendsReply_AndLearnsSender()
        {
            var port = new CaptureEthernetChannel();
            await using var arp = new ArpResolver(MacA, IpA, port);

            // B broadcasts: who has ipA?
            arp.HandleInboundFrame(ArpFrame(MacAddress.Broadcast, MacB, ArpPacket.BuildRequest(MacB, IpB, IpA)));

            byte[] reply = Assert.Single(port.Written);
            Assert.Equal(MacB, EthernetFrame.Destination(reply));        // unicast straight back to the asker
            Assert.Equal(MacA, EthernetFrame.Source(reply));
            byte[] repArp = EthernetFrame.Payload(reply).ToArray();
            Assert.Equal(ArpPacket.OperationReply, ArpPacket.Operation(repArp));
            Assert.Equal(MacA, ArpPacket.SenderMac(repArp));
            Assert.Equal(IpA, ArpPacket.SenderIp(repArp));
            Assert.Equal(MacB, ArpPacket.TargetMac(repArp));
            Assert.Equal(IpB, ArpPacket.TargetIp(repArp));

            // The request also taught us ipB→MacB, so a resolve needs no new request.
            ReadOnlyMemory<byte>? mac = await arp.ResolveAsync(IpB);
            Assert.Equal(MacB, MacAddress.FromBytes(mac!.Value.Span));
            Assert.Single(port.Written);
        }

        [Fact]
        public async Task Inbound_RequestForOtherIp_NoReply_ButLearns()
        {
            var port = new CaptureEthernetChannel();
            await using var arp = new ArpResolver(MacA, IpA, port);

            // B asks who has ipC (not us) — we stay silent but still learn B.
            arp.HandleInboundFrame(ArpFrame(MacAddress.Broadcast, MacB, ArpPacket.BuildRequest(MacB, IpB, IpC)));
            Assert.Empty(port.Written);

            ReadOnlyMemory<byte>? mac = await arp.ResolveAsync(IpB);
            Assert.Equal(MacB, MacAddress.FromBytes(mac!.Value.Span));
            Assert.Empty(port.Written);   // resolved from passive learning
        }

        [Fact]
        public async Task Inbound_UnsolicitedReply_JustLearns()
        {
            var port = new CaptureEthernetChannel();
            await using var arp = new ArpResolver(MacA, IpA, port);

            // A reply with no pending resolve must not throw and must still populate the cache.
            arp.HandleInboundFrame(ArpFrame(MacA, MacB, ArpPacket.BuildReply(MacB, IpB, MacA, IpA)));
            Assert.Empty(port.Written);

            ReadOnlyMemory<byte>? mac = await arp.ResolveAsync(IpB);
            Assert.Equal(MacB, MacAddress.FromBytes(mac!.Value.Span));
            Assert.Empty(port.Written);
        }

        [Fact]
        public async Task Inbound_RuntOrNonArp_Ignored()
        {
            var port = new CaptureEthernetChannel();
            await using var arp = new ArpResolver(MacA, IpA, port);

            arp.HandleInboundFrame(new byte[10]);   // shorter than the 14-byte Ethernet header
            arp.HandleInboundFrame(EthernetFrame.Build(MacA, MacB, EthernetFrame.EtherTypeIpv4, new byte[20]));   // not ARP

            Assert.Empty(port.Written);
        }

        [Fact]
        public async Task Dispose_CancelsPendingResolve()
        {
            var port = new CaptureEthernetChannel();
            var arp = new ArpResolver(MacA, IpA, port);

            ValueTask<ReadOnlyMemory<byte>?> pending = arp.ResolveAsync(IpB);   // no reply will arrive
            await arp.DisposeAsync();

            Assert.Null(await pending);
        }

        // ---- Integration: real ARP exchange between two hosts over the switch ----

        [Fact]
        public async Task Integration_TwoHostsArpOverSwitch_DeliversIpPacket()
        {
            await using var sw = new EthernetSwitch();
            IEthernetChannel portA = sw.ConnectHost(MacA);
            IEthernetChannel portB = sw.ConnectHost(MacB);
            await using var arpA = new ArpResolver(MacA, IpA, portA);
            await using var arpB = new ArpResolver(MacB, IpB, portB);
            await using var hostA = new VirtualHost(MacA, portA, arpA);
            await using var hostB = new VirtualHost(MacB, portB, arpB);
            hostA.InboundNonIpFrame += arpA.HandleInboundFrame;   // wire the L2.2 seam → ARP
            hostB.InboundNonIpFrame += arpB.HandleInboundFrame;
            byte[]? bGot = null;
            hostB.InboundIpPacket += p => bGot = p.ToArray();

            byte[] ip = Ipv4Packet(IpB, 1, 2, 3);
            await hostA.WriteIpPacketAsync(ip);   // egress A → ARP resolves ipB via real request/reply → wrap → B

            Assert.NotNull(bGot);
            Assert.Equal(ip, bGot);
        }

        // ---- Helpers ----

        static byte[] ArpFrame(MacAddress destination, MacAddress source, byte[] arpPayload)
            => EthernetFrame.Build(destination, source, EthernetFrame.EtherTypeArp, arpPayload);

        /// <summary>A minimal IPv4 packet: version nibble 4, destination at offset 16 (RFC 791), then payload.</summary>
        static byte[] Ipv4Packet(IPAddress destination, params byte[] payload)
        {
            byte[] packet = new byte[20 + payload.Length];
            packet[0] = 0x45;   // version 4, IHL 5
            destination.GetAddressBytes().CopyTo(packet, 16);
            payload.CopyTo(packet, 20);
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
