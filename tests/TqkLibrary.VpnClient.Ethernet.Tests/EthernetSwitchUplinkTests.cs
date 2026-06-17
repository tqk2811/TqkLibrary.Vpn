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
    /// <summary>
    /// The L2 multi-host data-plane: a VPN uplink (an external <see cref="IEthernetChannel"/>) attached to an
    /// <see cref="EthernetSwitch"/> / <see cref="EthernetAdapter"/> as an <i>uplink port</i> via <c>ConnectUplink</c>.
    /// Frames the switch floods/forwards go out the uplink (toward the tunnel peer), and frames arriving on the uplink
    /// are ingressed into the switch and forwarded to the right station — so the server answers ARP and serves DHCP per
    /// station over the shared broadcast domain. Pure offline — no network.
    /// </summary>
    public class EthernetSwitchUplinkTests
    {
        static readonly MacAddress MacA = MacAddress.Parse("02:00:00:00:00:0a");
        static readonly MacAddress MacB = MacAddress.Parse("02:00:00:00:00:0b");
        static readonly MacAddress ServerMac = MacAddress.Parse("02:00:00:00:00:01");

        static readonly IPAddress IpA = IPAddress.Parse("10.0.0.10");
        static readonly IPAddress IpB = IPAddress.Parse("10.0.0.11");

        static ArpResolverOptions FastArp => new ArpResolverOptions(cacheTtl: TimeSpan.FromSeconds(20), requestTimeout: TimeSpan.FromMilliseconds(200), maxAttempts: 5);

        static byte[] Frame(MacAddress destination, MacAddress source) =>
            EthernetFrame.Build(destination, source, EthernetFrame.EtherTypeIpv4, new byte[] { 1, 2, 3, 4 });

        // ---- Egress: broadcast/unknown-unicast frames flood out the uplink toward the tunnel peer ----

        [Fact]
        public async Task SwitchFlood_GoesOutTheUplink()
        {
            await using var sw = new EthernetSwitch();
            var uplink = new RecordingUplink();
            await using EthernetSwitch.UplinkPortHandle handle = sw.ConnectUplink(uplink);

            IEthernetChannel host = sw.ConnectHost(MacA);
            // An unknown-unicast from the host floods to every other port — including the uplink.
            await host.WriteFrameAsync(Frame(MacB, MacA));

            Assert.Single(uplink.Sent);
            Assert.Equal(MacB, EthernetFrame.Destination(uplink.Sent[0]));
        }

        // ---- Ingress: a frame arriving on the uplink is forwarded to the addressed station, not reflected ----

        [Fact]
        public async Task UplinkInbound_IsForwardedToTheAddressedStation()
        {
            await using var sw = new EthernetSwitch();
            var uplink = new RecordingUplink();
            sw.ConnectUplink(uplink);

            IEthernetChannel host = sw.ConnectHost(MacA);
            var rxHost = new List<byte[]>();
            host.InboundFrame += f => rxHost.Add(f.ToArray());

            // The host transmits so the switch learns MacA → the host port.
            await host.WriteFrameAsync(Frame(ServerMac, MacA));
            uplink.Sent.Clear();

            // The server (behind the uplink) sends a unicast to MacA: it ingresses and is forwarded only to the host.
            uplink.InjectInbound(Frame(MacA, ServerMac));

            Assert.Single(rxHost);
            Assert.Equal(MacA, EthernetFrame.Destination(rxHost[0]));
            Assert.Empty(uplink.Sent);   // not reflected back out the uplink
        }

        // ---- Lifecycle: detaching the uplink stops both directions and unsubscribes ----

        [Fact]
        public async Task DisposingTheHandle_DetachesTheUplink_StopsBothDirections()
        {
            await using var sw = new EthernetSwitch();
            var uplink = new RecordingUplink();
            EthernetSwitch.UplinkPortHandle handle = sw.ConnectUplink(uplink);
            Assert.Equal(1, sw.PortCount);

            IEthernetChannel host = sw.ConnectHost(MacA);
            await handle.DisposeAsync();
            Assert.Equal(1, sw.PortCount);   // only the host remains

            // Egress no longer reaches the detached uplink, and an injected inbound frame is ignored.
            await host.WriteFrameAsync(Frame(MacB, MacA));
            Assert.Empty(uplink.Sent);
            var rxHost = new List<byte[]>();
            host.InboundFrame += f => rxHost.Add(f.ToArray());
            uplink.InjectInbound(Frame(MacA, ServerMac));
            Assert.Empty(rxHost);
        }

        // ---- Two stations on one uplink exchange IP over the shared switch, the server bridging only as needed ----

        [Fact]
        public async Task TwoStationsOnOneUplink_ExchangeIpOverTheSharedSwitch()
        {
            await using var adapter = new EthernetAdapter();
            var uplink = new RecordingUplink();
            adapter.ConnectUplink(uplink);

            EthernetAdapter.EthernetHostHandle a = adapter.AddHost(MacA, port =>
            {
                var arp = new ArpResolver(MacA, IpA, port, FastArp);
                return new EthernetHostSpec(arp) { NonIpFrameHandler = arp.HandleInboundFrame };
            });
            EthernetAdapter.EthernetHostHandle b = adapter.AddHost(MacB, port =>
            {
                var arp = new ArpResolver(MacB, IpB, port, FastArp);
                return new EthernetHostSpec(arp) { NonIpFrameHandler = arp.HandleInboundFrame };
            });

            var bInbox = new InboundCollector(b.Channel);
            byte[] packet = Ipv4Packet(IpA, IpB, 7, 7, 7);
            await a.Channel.WriteIpPacketAsync(packet);

            // A ARPs for IpB → floods (incl. out the uplink) + reaches B; B answers; the IP packet then reaches B.
            byte[] got = await bInbox.WaitForOneAsync();
            Assert.Equal(packet, got);
        }

        // ---- A station leases its IP over the uplink from a DHCP server behind it (the multi-host data-plane) ----

        [Fact]
        public async Task StationLeasesAddressFromADhcpServerBehindTheUplink()
        {
            await using var session = new MultiHostSession(new EthernetAdapter());
            var uplink = new RecordingUplink();
            session.Adapter.ConnectUplink(uplink);
            using var server = new DhcpAndArpServer(uplink);

            ArpResolver? arpRef = null;
            EthernetHostSession station = await session.AddStationAsync(MacA, port =>
            {
                var arp = new ArpResolver(MacA, IPAddress.Any, port, FastArp);
                arpRef = arp;
                var dhcp = new DhcpV4Configurator(MacA, port, new DhcpV4ConfiguratorOptions(replyTimeout: TimeSpan.FromMilliseconds(200), maxAttempts: 5));
                return new EthernetHostSpec(arp)
                {
                    Configurator = dhcp,
                    NonIpFrameHandler = arp.HandleInboundFrame,
                    IpPacketHandler = dhcp.HandleInboundFrame,
                };
            });
            arpRef!.SetLocalAddress(station.Config.AssignedAddress!);

            Assert.Equal(DhcpAndArpServer.Offered, station.Config.AssignedAddress);
            Assert.Equal(24, station.Config.PrefixLength);
            Assert.Equal(DhcpAndArpServer.Offered, arpRef.Address);   // ARP now answers for the leased address
        }

        // ---- Helpers ----

        static byte[] Ipv4Packet(IPAddress source, IPAddress destination, params byte[] payload)
        {
            byte[] packet = new byte[20 + payload.Length];
            packet[0] = 0x45;
            source.GetAddressBytes().CopyTo(packet, 12);
            destination.GetAddressBytes().CopyTo(packet, 16);
            payload.CopyTo(packet, 20);
            return packet;
        }

        /// <summary>
        /// A test uplink channel: records every frame the switch sends out (and raises <see cref="OnSent"/> so a server
        /// can react), and lets the test inject inbound frames as if arriving from the tunnel peer.
        /// </summary>
        sealed class RecordingUplink : IEthernetChannel
        {
            public readonly List<byte[]> Sent = new();

            /// <summary>Raised for each frame the switch forwards out the uplink (toward the tunnel peer).</summary>
            public event Action<byte[]>? OnSent;

            public LinkMedium Medium => LinkMedium.Ethernet;
            public int Mtu => 1500;
            public int MaxHeaderLength => EthernetFrame.HeaderLength;
            public bool RequiresLinkAddressResolution => true;
            public ReadOnlyMemory<byte> LinkAddress => ServerMac.ToArray();
            public event Action<ReadOnlyMemory<byte>>? InboundFrame;

            public ValueTask WriteFrameAsync(ReadOnlyMemory<byte> ethernetFrame, CancellationToken cancellationToken = default)
            {
                byte[] copy = ethernetFrame.ToArray();
                lock (Sent) Sent.Add(copy);
                OnSent?.Invoke(copy);
                return default;
            }

            /// <summary>Simulates a frame arriving from the tunnel peer (the switch ingresses it).</summary>
            public void InjectInbound(byte[] frame) => InboundFrame?.Invoke(frame);

            public ValueTask DisposeAsync() => default;
        }

        /// <summary>
        /// A server behind the uplink: it watches every frame the switch sends out, answers ARP requests (it owns every
        /// address) and DHCP DISCOVER/REQUEST (a /24 pool), and injects the replies back over the uplink.
        /// </summary>
        sealed class DhcpAndArpServer : IDisposable
        {
            public static readonly IPAddress Offered = IPAddress.Parse("10.0.0.50");
            static readonly IPAddress ServerId = IPAddress.Parse("10.0.0.1");
            static readonly IPAddress Mask = IPAddress.Parse("255.255.255.0");
            static readonly IPAddress Router = IPAddress.Parse("10.0.0.1");
            static readonly IPAddress Dns = IPAddress.Parse("8.8.8.8");

            readonly RecordingUplink _uplink;

            public DhcpAndArpServer(RecordingUplink uplink)
            {
                _uplink = uplink;
                _uplink.OnSent += OnOutbound;           // react to every frame the switch forwards out the uplink
            }

            void OnOutbound(byte[] frame)
            {
                if (frame.Length < EthernetFrame.HeaderLength) return;
                ushort etherType = EthernetFrame.EtherType(frame);
                MacAddress clientMac = EthernetFrame.Source(frame);

                if (etherType == EthernetFrame.EtherTypeArp)
                {
                    ReadOnlySpan<byte> arp = EthernetFrame.Payload(frame).Span;
                    if (!ArpPacket.IsIpv4OverEthernet(arp) || ArpPacket.Operation(arp) != ArpPacket.OperationRequest) return;
                    MacAddress senderMac = ArpPacket.SenderMac(arp);
                    IPAddress senderIp = ArpPacket.SenderIp(arp);
                    IPAddress targetIp = ArpPacket.TargetIp(arp);
                    _uplink.InjectInbound(EthernetFrame.Build(senderMac, ServerMac, EthernetFrame.EtherTypeArp,
                        ArpPacket.BuildReply(ServerMac, targetIp, senderMac, senderIp)));
                    return;
                }

                if (etherType == EthernetFrame.EtherTypeIpv4)
                    TryAnswerDhcp(EthernetFrame.Payload(frame), clientMac);
            }

            void TryAnswerDhcp(ReadOnlyMemory<byte> ip, MacAddress clientMac)
            {
                ReadOnlySpan<byte> span = ip.Span;
                if (span.Length < 9 || (byte)(span[0] >> 4) != 4 || span[9] != 17) return;
                int ihl = (span[0] & 0x0F) * 4;
                int destPort = (span[ihl + 2] << 8) | span[ihl + 3];
                if (destPort != DhcpV4Packet.ServerPort) return;
                byte[] dhcp = ip.Slice(ihl + 8).ToArray();
                if (dhcp.Length < DhcpV4Packet.HeaderLength + 4 || dhcp[0] != DhcpV4Packet.OpBootRequest
                    || !DhcpV4Options.HasMagicCookie(DhcpV4Packet.OptionField(dhcp).Span))
                    return;
                uint xid = DhcpV4Packet.Xid(dhcp);
                byte type = DhcpV4Options.ReadMessageType(DhcpV4Packet.OptionField(dhcp).Span);
                byte replyType = type == DhcpV4Options.MessageDiscover ? DhcpV4Options.MessageOffer
                    : type == DhcpV4Options.MessageRequest ? DhcpV4Options.MessageAck
                    : (byte)0;
                if (replyType == 0) return;
                _uplink.InjectInbound(BuildReply(replyType, xid, clientMac));
            }

            static byte[] BuildReply(byte messageType, uint xid, MacAddress clientMac)
            {
                byte[] options = new byte[128];
                int pos = DhcpV4Options.WriteMagicCookie(options, 0);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeMessageType, messageType);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeServerId, ServerId);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeSubnetMask, Mask);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeRouter, Router);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeDnsServer, Dns.GetAddressBytes());
                pos = DhcpV4Options.WriteEnd(options, pos);

                byte[] msg = DhcpV4Packet.Build(xid, clientMac, requestedCiaddr: null, broadcast: false, options.AsSpan(0, pos));
                msg[0] = DhcpV4Packet.OpBootReply;
                Offered.GetAddressBytes().CopyTo(msg, 16);   // yiaddr @ offset 16

                byte[] udpIp = DhcpV4Packet.BuildUdpIpv4(ServerId, IPAddress.Broadcast,
                    DhcpV4Packet.ServerPort, DhcpV4Packet.ClientPort, msg);
                return EthernetFrame.Build(MacAddress.Broadcast, ServerMac, EthernetFrame.EtherTypeIpv4, udpIp);
            }

            public void Dispose() => _uplink.OnSent -= OnOutbound;
        }

        sealed class InboundCollector
        {
            readonly List<byte[]> _packets = new();
            public InboundCollector(IPacketChannel channel) => channel.InboundIpPacket += p =>
            {
                lock (_packets) _packets.Add(p.ToArray());
            };
            public async Task<byte[]> WaitForOneAsync()
            {
                for (int i = 0; i < 200; i++)
                {
                    lock (_packets)
                        if (_packets.Count > 0) return _packets[0];
                    await Task.Delay(5);
                }
                throw new TimeoutException("No inbound IP packet arrived.");
            }
        }
    }
}
