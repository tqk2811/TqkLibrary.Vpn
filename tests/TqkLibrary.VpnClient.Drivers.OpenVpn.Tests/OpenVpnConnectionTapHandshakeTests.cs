using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Ethernet;
using TqkLibrary.VpnClient.OpenVpn;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using TqkLibrary.VpnClient.OpenVpn.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.OpenVpn.Tests
{
    /// <summary>
    /// Drives the OpenVPN driver in <b>tap-mode</b> (<c>dev tap</c>) offline: the real <see cref="OpenVpnConnection"/>
    /// negotiates exactly as in tun-mode, then binds the Ethernet data channel through the userspace L2 fabric
    /// (<c>OpenVpnTapChannel → ArpResolver + VirtualHost</c>) and exposes a bare L3 <c>IPacketChannel</c> — so the
    /// consumer still sees IP. The test proves the round-trip survives ARP: the client ARPs for the gateway, the server
    /// answers, the IP packet is then framed in Ethernet, echoed, and the inner IP resurfaces on the facade. A keepalive
    /// ping is dropped, not delivered. The responder is throwaway test scaffolding (this library is a client).
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
        public async Task Connect_TapMode_NoIfconfig_PointsToDhcpRoadmap()
        {
            var link = new LoopbackLink();
            using var serverCert = OpenVpnTestPki.CreateSelfSignedServerCert();
            using var server = new SimulatedOpenVpnTapServer(link.Server, serverCert, pushReply: $"PUSH_REPLY,peer-id 7,cipher AES-256-GCM");

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var connection = new OpenVpnConnection("127.0.0.1", 1194, new InProcessTransportFactory(link.Client),
                optionsString: "V4,cipher AES-256-GCM",
                device: OpenVpnDeviceType.Tap,
                serverCertificateValidation: (_, _, _, _) => true,
                reliabilityOptions: new OpenVpnReliabilityOptions { Interval = TimeSpan.FromSeconds(30) });

            // A pure DHCP bridge (no pushed ifconfig) is refused with a message pointing at the userspace DHCPv4 client (L2.5).
            VpnServerRejectedException ex = await Assert.ThrowsAsync<VpnServerRejectedException>(() => connection.ConnectAsync(cts.Token));
            Assert.Contains("L2.5", ex.Message);

            await connection.DisposeAsync();
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
        /// requests (the server owns every gateway IP the client asks for), and echoes inner IP packets back re-framed
        /// toward the client. Mirrors a server-bridge that pushes ifconfig — no DHCP.
        /// </summary>
        sealed class SimulatedOpenVpnTapServer : SimulatedOpenVpnServerBase
        {
            static readonly MacAddress ServerMac = MacAddress.Parse("02:00:5e:00:00:01");
            readonly string _push;
            MacAddress _clientMac;

            public SimulatedOpenVpnTapServer(IOpenVpnTransport transport, X509Certificate2 certificate, string? pushReply = null)
                : base(transport, certificate) => _push = pushReply
                    ?? $"PUSH_REPLY,ifconfig 10.8.0.2 255.255.255.0,topology subnet,peer-id {PeerId},cipher AES-256-GCM";

            protected override string PushReply => _push;

            protected override void OnData(byte[] frame)
            {
                if (frame.Length < EthernetFrame.HeaderLength) return;
                _clientMac = EthernetFrame.Source(frame);
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

                if (etherType == EthernetFrame.EtherTypeIpv4 || etherType == EthernetFrame.EtherTypeIpv6)
                    SendIpToClient(EthernetFrame.Payload(frame).ToArray());   // echo the inner IP back, re-framed to the client
            }

            /// <summary>Test stimulus: frame a bare IP packet toward the client and send it over the data channel.</summary>
            public void SendIpToClient(byte[] ipPacket)
            {
                ushort etherType = (ipPacket.Length > 0 && (ipPacket[0] >> 4) == 6)
                    ? EthernetFrame.EtherTypeIpv6 : EthernetFrame.EtherTypeIpv4;
                SendData(EthernetFrame.Build(_clientMac, ServerMac, etherType, ipPacket));
            }
        }
    }
}
