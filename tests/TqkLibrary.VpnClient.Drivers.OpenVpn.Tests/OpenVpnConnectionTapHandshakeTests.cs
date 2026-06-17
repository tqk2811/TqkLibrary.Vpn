using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Ethernet;
using TqkLibrary.VpnClient.OpenVpn;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using TqkLibrary.VpnClient.OpenVpn.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.OpenVpn.Tests
{
    /// <summary>
    /// Drives the OpenVPN driver in <b>tap-mode</b> (<c>dev tap</c>) offline: the real <see cref="OpenVpnConnection"/>
    /// negotiates exactly as in tun-mode, then binds the Ethernet data channel through the userspace L2 fabric and
    /// exposes a bare L3 <c>IPacketChannel</c> — so the consumer still sees IP. Covers the single-host ifconfig bridge,
    /// the pure-DHCP bridge (no pushed ifconfig → DHCPv4 lease over the L2 segment, L2.5), and the multi-host broadcast
    /// domain (the tap channel attached as an uplink port; N stations leasing their own IP, L2.7/L2.8). The responder is
    /// throwaway test scaffolding (this library is a client).
    /// </summary>
    public class OpenVpnConnectionTapHandshakeTests
    {
        [Fact]
        public async Task Connect_TapMode_BridgesEthernet_BindsAddress_RoundTripsIp_AndDropsPing()
        {
            var link = new LoopbackLink();
            using var serverCert = OpenVpnTestPki.CreateSelfSignedServerCert();
            using var server = new SimulatedOpenVpnTapServer(link.Server, serverCert);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new OpenVpnConnection("127.0.0.1", 1194, new InProcessTransportFactory(link.Client),
                optionsString: "V4,cipher AES-256-GCM",
                device: OpenVpnDeviceType.Tap,
                serverCertificateValidation: (_, _, _, _) => true,
                reliabilityOptions: new OpenVpnReliabilityOptions { Interval = TimeSpan.FromSeconds(30) });

            var inbound = Channel.CreateUnbounded<byte[]>();
            connection.PacketChannel.InboundIpPacket += m => inbound.Writer.TryWrite(m.ToArray());

            await connection.ConnectAsync(cts.Token);

            // PUSH_REPLY (server-bridge managed pool) bound the tunnel address through the L2 bridge.
            Assert.Equal(IPAddress.Parse("10.8.0.2"), connection.AssignedAddress);
            Assert.Equal(24, connection.Config.PrefixLength);
            // The bound channel reports the L3 (Ip) medium with MTU reduced by the 14-byte Ethernet header.
            Assert.Equal(1486, connection.PacketChannel.Mtu);

            // A real IPv4 packet to the gateway: VirtualHost ARPs for 10.8.0.1, the server answers, the packet is framed
            // in Ethernet, the server echoes the inner IP back, and the bare IP resurfaces on the L3 facade.
            byte[] ip = BuildIpv4Packet(IPAddress.Parse("10.8.0.2"), IPAddress.Parse("10.8.0.1"), Encoding.ASCII.GetBytes("tap round-trip over Ethernet"));
            await connection.PacketChannel.WriteIpPacketAsync(ip, cts.Token);
            byte[] echoed = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(ip, echoed);

            // The server sends a keepalive ping (bare magic, not Ethernet-framed) then a normal IP frame: the ping must be
            // dropped at the data link, only the IP frame delivered.
            server.SendDataToClient(OpenVpnPing.Magic.ToArray());
            byte[] sentinel = BuildIpv4Packet(IPAddress.Parse("10.8.0.1"), IPAddress.Parse("10.8.0.2"), Encoding.ASCII.GetBytes("the IP frame after the ping"));
            server.SendIpToClient(sentinel);
            byte[] afterPing = await inbound.Reader.ReadAsync(cts.Token);
            Assert.Equal(sentinel, afterPing);

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task Connect_TapMode_PureDhcp_NoPushedIfconfig_LeasesAddressOverTheSegment()
        {
            var link = new LoopbackLink();
            using var serverCert = OpenVpnTestPki.CreateSelfSignedServerCert();
            // The server pushes no ifconfig but runs a DHCP server behind the bridge (server-bridge with a DHCP pool).
            using var server = new SimulatedOpenVpnTapServer(link.Server, serverCert,
                pushReply: $"PUSH_REPLY,peer-id 7,cipher AES-256-GCM", dhcpServer: true);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new OpenVpnConnection("127.0.0.1", 1194, new InProcessTransportFactory(link.Client),
                optionsString: "V4,cipher AES-256-GCM",
                device: OpenVpnDeviceType.Tap,
                serverCertificateValidation: (_, _, _, _) => true,
                reliabilityOptions: new OpenVpnReliabilityOptions { Interval = TimeSpan.FromSeconds(30) });

            await connection.ConnectAsync(cts.Token);

            // No ifconfig was pushed, yet the userspace DHCPv4 client (L2.5) leased an address from the bridge's pool.
            Assert.Equal(SimulatedOpenVpnTapServer.DhcpOffered, connection.AssignedAddress);
            Assert.Equal(24, connection.Config.PrefixLength);
            Assert.Equal(1486, connection.PacketChannel.Mtu);

            await connection.DisposeAsync();
        }

        [Fact]
        public async Task Connect_TapMode_MultiHost_PrimaryUsesPushedIfconfig_AndOpenSessionAddsADhcpStation()
        {
            var link = new LoopbackLink();
            using var serverCert = OpenVpnTestPki.CreateSelfSignedServerCert();
            // Pushes ifconfig for the primary AND runs DHCP behind the bridge for additional stations.
            using var server = new SimulatedOpenVpnTapServer(link.Server, serverCert, dhcpServer: true);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new OpenVpnConnection("127.0.0.1", 1194, new InProcessTransportFactory(link.Client),
                optionsString: "V4,cipher AES-256-GCM",
                device: OpenVpnDeviceType.Tap,
                serverCertificateValidation: (_, _, _, _) => true,
                multiHost: true,
                reliabilityOptions: new OpenVpnReliabilityOptions { Interval = TimeSpan.FromSeconds(30) });

            await connection.ConnectAsync(cts.Token);

            Assert.True(connection.IsMultiHost);
            Assert.NotNull(connection.MultiHostSession);
            // The primary station took the pushed ifconfig; the data channel is an uplink port + one station.
            Assert.Equal(IPAddress.Parse("10.8.0.2"), connection.AssignedAddress);
            Assert.Equal(1, connection.MultiHostSession!.StationCount);
            Assert.Equal(2, connection.MultiHostSession.Adapter.Switch.PortCount);   // uplink + the primary station

            var vpnConnection = new OpenVpnVpnConnection(connection, new OpenVpnVpnSession(connection.PacketChannel, connection.Config));

            // A second station leases its own IP from the bridge's DHCP server over the shared switch.
            IVpnSession station2 = await vpnConnection.OpenSessionAsync(cts.Token);
            Assert.Equal(SimulatedOpenVpnTapServer.DhcpOffered, station2.Config.AssignedAddress);
            Assert.Equal(2, connection.MultiHostSession.StationCount);
            Assert.Equal(2, vpnConnection.Sessions.Count);
            Assert.NotSame(connection.PacketChannel, station2.PacketChannel);

            await vpnConnection.DisposeAsync();
        }

        // A minimal but well-formed IPv4 packet: VirtualHost reads only the version nibble + destination @ offset 16.
        static byte[] BuildIpv4Packet(IPAddress source, IPAddress destination, byte[] payload)
        {
            byte[] packet = new byte[20 + payload.Length];
            packet[0] = 0x45;                                   // version 4, IHL 5 (20-byte header)
            packet[2] = (byte)(packet.Length >> 8);
            packet[3] = (byte)packet.Length;                    // total length
            packet[8] = 64;                                     // TTL
            packet[9] = 17;                                     // protocol (UDP — irrelevant to the bridge)
            source.GetAddressBytes().CopyTo(packet, 12);
            destination.GetAddressBytes().CopyTo(packet, 16);
            payload.CopyTo(packet, 20);
            return packet;
        }

        /// <summary>
        /// tap responder: each decrypted P_DATA payload is a full Ethernet frame. It learns the client's MAC, answers ARP
        /// requests (the server owns every gateway IP the client asks for), echoes inner IP packets back re-framed toward
        /// the client, and — when <c>dhcpServer</c> is set — answers DHCP DISCOVER/REQUEST from a /24 pool (a server-bridge
        /// with a DHCP server). The ARP/DHCP/echo replies are broadcast/unicast back over the same data channel; in
        /// multi-host the in-memory switch forwards them to the right station.
        /// </summary>
        sealed class SimulatedOpenVpnTapServer : SimulatedOpenVpnServerBase
        {
            public static readonly IPAddress DhcpOffered = IPAddress.Parse("10.8.0.50");
            static readonly IPAddress DhcpServerId = IPAddress.Parse("10.8.0.1");
            static readonly IPAddress DhcpMask = IPAddress.Parse("255.255.255.0");
            static readonly IPAddress DhcpRouter = IPAddress.Parse("10.8.0.1");
            static readonly IPAddress DhcpDns = IPAddress.Parse("8.8.8.8");
            static readonly MacAddress ServerMac = MacAddress.Parse("02:00:5e:00:00:01");

            readonly string _push;
            readonly bool _dhcpServer;

            public SimulatedOpenVpnTapServer(IOpenVpnTransport transport, X509Certificate2 certificate, string? pushReply = null, bool dhcpServer = false)
                : base(transport, certificate)
            {
                _push = pushReply ?? $"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,topology subnet,peer-id {PeerId},cipher AES-256-GCM";
                _dhcpServer = dhcpServer;
            }

            protected override string PushReply => _push;

            protected override void OnData(byte[] frame)
            {
                if (frame.Length < EthernetFrame.HeaderLength) return;
                MacAddress clientMac = EthernetFrame.Source(frame);
                _lastClientMac = clientMac;
                ushort etherType = EthernetFrame.EtherType(frame);

                if (etherType == EthernetFrame.EtherTypeArp)
                {
                    ReadOnlySpan<byte> arp = EthernetFrame.Payload(frame).Span;
                    if (!ArpPacket.IsIpv4OverEthernet(arp) || ArpPacket.Operation(arp) != ArpPacket.OperationRequest) return;
                    MacAddress senderMac = ArpPacket.SenderMac(arp);
                    IPAddress senderIp = ArpPacket.SenderIp(arp);
                    IPAddress targetIp = ArpPacket.TargetIp(arp);
                    // The server is the gateway for every address the client resolves: answer "targetIp is at ServerMac".
                    byte[] reply = EthernetFrame.Build(senderMac, ServerMac, EthernetFrame.EtherTypeArp,
                        ArpPacket.BuildReply(ServerMac, targetIp, senderMac, senderIp));
                    SendData(reply);
                    return;
                }

                if (etherType == EthernetFrame.EtherTypeIpv4)
                {
                    if (_dhcpServer && TryAnswerDhcp(EthernetFrame.Payload(frame), clientMac)) return;
                    SendIpToClient(EthernetFrame.Payload(frame).ToArray(), clientMac);   // echo the inner IP back, re-framed
                    return;
                }

                if (etherType == EthernetFrame.EtherTypeIpv6)
                    SendIpToClient(EthernetFrame.Payload(frame).ToArray(), clientMac);
            }

            // Answers a DHCP DISCOVER with an OFFER and a REQUEST with an ACK (a /24 pool). Returns false if not DHCP.
            bool TryAnswerDhcp(ReadOnlyMemory<byte> ip, MacAddress clientMac)
            {
                ReadOnlySpan<byte> span = ip.Span;
                if (span.Length < 1 || (byte)(span[0] >> 4) != 4 || span.Length < 9 || span[9] != 17) return false;
                int ihl = (span[0] & 0x0F) * 4;
                if (span.Length < ihl + 4) return false;
                int destPort = (span[ihl + 2] << 8) | span[ihl + 3];
                if (destPort != DhcpV4Packet.ServerPort) return false;
                byte[] dhcp = ip.Slice(ihl + 8).ToArray();
                if (dhcp.Length < DhcpV4Packet.HeaderLength + 4 || dhcp[0] != DhcpV4Packet.OpBootRequest
                    || !DhcpV4Options.HasMagicCookie(DhcpV4Packet.OptionField(dhcp).Span))
                    return false;
                uint xid = DhcpV4Packet.Xid(dhcp);
                byte type = DhcpV4Options.ReadMessageType(DhcpV4Packet.OptionField(dhcp).Span);
                byte replyType = type == DhcpV4Options.MessageDiscover ? DhcpV4Options.MessageOffer
                    : type == DhcpV4Options.MessageRequest ? DhcpV4Options.MessageAck
                    : (byte)0;
                if (replyType == 0) return false;
                SendData(BuildDhcpReply(replyType, xid, clientMac));
                return true;
            }

            static byte[] BuildDhcpReply(byte messageType, uint xid, MacAddress clientMac)
            {
                byte[] options = new byte[128];
                int pos = DhcpV4Options.WriteMagicCookie(options, 0);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeMessageType, messageType);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeServerId, DhcpServerId);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeSubnetMask, DhcpMask);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeRouter, DhcpRouter);
                pos = DhcpV4Options.WriteOption(options, pos, DhcpV4Options.CodeDnsServer, DhcpDns.GetAddressBytes());
                pos = DhcpV4Options.WriteEnd(options, pos);

                byte[] msg = DhcpV4Packet.Build(xid, clientMac, requestedCiaddr: null, broadcast: false, options.AsSpan(0, pos));
                msg[0] = DhcpV4Packet.OpBootReply;
                DhcpOffered.GetAddressBytes().CopyTo(msg, 16);   // yiaddr @ offset 16

                byte[] udpIp = DhcpV4Packet.BuildUdpIpv4(DhcpServerId, IPAddress.Broadcast,
                    DhcpV4Packet.ServerPort, DhcpV4Packet.ClientPort, msg);
                return EthernetFrame.Build(clientMac, ServerMac, EthernetFrame.EtherTypeIpv4, udpIp);
            }

            /// <summary>Test stimulus: frame a bare IP packet toward the client (default MAC) and send it.</summary>
            public void SendIpToClient(byte[] ipPacket) => SendIpToClient(ipPacket, _lastClientMac);

            void SendIpToClient(byte[] ipPacket, MacAddress clientMac)
            {
                _lastClientMac = clientMac;
                ushort etherType = (ipPacket.Length > 0 && (ipPacket[0] >> 4) == 6)
                    ? EthernetFrame.EtherTypeIpv6 : EthernetFrame.EtherTypeIpv4;
                SendData(EthernetFrame.Build(clientMac, ServerMac, etherType, ipPacket));
            }

            MacAddress _lastClientMac;
        }
    }
}
