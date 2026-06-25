using System.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.N2n.Transport;
using TqkLibrary.VpnClient.Ethernet;
using TqkLibrary.VpnClient.N2n;
using TqkLibrary.VpnClient.N2n.Transform;
using TqkLibrary.VpnClient.N2n.Transform.Interfaces;
using TqkLibrary.VpnClient.N2n.Wire.Models;

namespace TqkLibrary.VpnClient.Drivers.N2n.Tests
{
    /// <summary>
    /// An in-memory connected UDP loopback that ties the real <see cref="N2nConnection"/> to an in-process supernode
    /// built from the same protocol blocks (<see cref="N2nPacketCodec"/> + the Ethernet/ARP codecs). Lossless + ordered,
    /// each send delivered to the peer on the thread pool. Throwaway test scaffolding — the library is a client; the
    /// supernode role exists only here. Mirrors the Nebula / SoftEther driver loopback harnesses.
    /// </summary>
    sealed class LoopbackUdpLink
    {
        readonly Endpoint _client = new();
        readonly Endpoint _server = new();

        public LoopbackUdpLink() { _client.Peer = _server; _server.Peer = _client; }

        public Endpoint Client => _client;
        public Endpoint Server => _server;

        public sealed class Endpoint : IDatagramTransport
        {
            public Endpoint? Peer;
            readonly object _lock = new();
            Task _tail = Task.CompletedTask;
            Action<ReadOnlyMemory<byte>>? _receiver;

            public void SetReceiver(Action<ReadOnlyMemory<byte>> receiver) => _receiver = receiver;

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

            public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
            {
                byte[] copy = datagram.ToArray();
                Endpoint? peer = Peer;
                if (peer != null)
                    lock (peer._lock)
                        peer._tail = peer._tail.ContinueWith(_ => peer._receiver?.Invoke(copy), TaskScheduler.Default);
                return default;
            }

            public ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
                => throw new NotSupportedException("The loopback link self-pumps via the registered receiver.");

            public ValueTask DisposeAsync() => default;
        }
    }

    /// <summary>An <see cref="IN2nTransportFactory"/> that hands back a fixed in-process pipe (self-pumping loopback).</summary>
    sealed class InProcessN2nTransportFactory : IN2nTransportFactory
    {
        readonly LoopbackUdpLink.Endpoint _endpoint;
        public InProcessN2nTransportFactory(LoopbackUdpLink.Endpoint endpoint) => _endpoint = endpoint;

        public Task<N2nTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken)
            => Task.FromResult(new N2nTransportHandle(_endpoint, _endpoint.SetReceiver, receivePump: null));
    }

    /// <summary>
    /// A throwaway n2n supernode + gateway-edge: it answers REGISTER_SUPER with a REGISTER_SUPER_ACK (echoing the cookie,
    /// assigning a subnet), then for every inbound PACKET it decodes the encapsulated Ethernet frame, answers ARP for the
    /// gateway, and echoes inbound IPv4 unicast frames back (swapping MAC src/dst) — re-wrapping each reply as a PACKET.
    /// Re-implemented from n2n's protocol behavior; no GPL source.
    /// </summary>
    sealed class SimulatedN2nSupernode : IDisposable
    {
        readonly LoopbackUdpLink.Endpoint _transport;
        readonly string _community;
        readonly N2nPacketCodec _codec = new();
        readonly IN2nTransform _transform;
        readonly N2nHeaderEncryption? _headerEnc;     // non-null mirrors a supernode/edge running with -H
        readonly MacAddress _gatewayMac;
        readonly IPAddress _gateway;
        readonly object _sync = new();

        MacAddress? _clientMac;     // learned from the first REGISTER_SUPER / PACKET srcMac

        public int RegisterSuperCount { get; private set; }
        public int PacketCount { get; private set; }
        public byte[]? SnMac { get; }

        public SimulatedN2nSupernode(LoopbackUdpLink.Endpoint transport, string community, IPAddress gateway,
            IN2nTransform? transform = null, bool headerEncryption = false)
        {
            _transport = transport;
            _community = community;
            _gateway = gateway;
            _transform = transform ?? new N2nNullTransform();
            _headerEnc = headerEncryption ? new N2nHeaderEncryption(community) : null;
            _gatewayMac = MacAddress.Parse("5e:00:00:00:7e:01");
            SnMac = MacAddress.Parse("5e:00:00:00:7e:00").ToArray();
            _transport.SetReceiver(OnInbound);
        }

        static ulong Stamp() => (ulong)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).Ticks / 10UL;

        /// <summary>The gateway MAC the supernode answers ARP with (the next-hop the client resolves before echoing).</summary>
        public MacAddress GatewayMac => _gatewayMac;

        void OnInbound(ReadOnlyMemory<byte> datagram)
        {
            byte[] buffer = datagram.ToArray();
            if (_headerEnc is not null && !N2nPacketCodec.TryDecryptHeader(buffer, _headerEnc, out _)) return;
            ReadOnlySpan<byte> span = buffer;
            if (!_codec.TryPeekHeader(span, out N2nCommonHeader header)) return;

            switch (header.PacketType)
            {
                case TqkLibrary.VpnClient.N2n.Wire.Enums.N2nPacketType.RegisterSuper: HandleRegisterSuper(span); break;
                case TqkLibrary.VpnClient.N2n.Wire.Enums.N2nPacketType.Packet: HandlePacket(span); break;
                default: break;
            }
        }

        void HandleRegisterSuper(ReadOnlySpan<byte> span)
        {
            if (!_codec.TryDecodeRegisterSuper(span, out _, out N2nRegisterSuper reg)) return;
            RegisterSuperCount++;
            lock (_sync) _clientMac ??= MacAddress.FromBytes(reg.EdgeMac);

            // Assign a /24 the edge could use (the edge keeps its own static address, but a real supernode replies with one).
            byte[] gw = _gateway.GetAddressBytes();
            uint net = ((uint)gw[0] << 24) | ((uint)gw[1] << 16) | ((uint)gw[2] << 8) | gw[3];
            var ack = new N2nRegisterSuperAck
            {
                Cookie = reg.Cookie,
                SrcMac = SnMac!,
                DevAddr = new N2nIpSubnet(net, 24),
                Lifetime = 60,
                Sock = new N2nSock { IsIpv6 = false, Port = 50000, Address = new byte[] { 100, 64, 0, 9 } },
                Auth = reg.Auth,
                NumSn = 0,
                ExtraSupernodes = Array.Empty<N2nSock>(),
                KeyTime = 0,
            };
            byte[] datagram = _codec.EncodeRegisterSuperAck(_community, ack);
            // A supernode running -H header-encrypts the whole ACK (control message: header_len = length).
            N2nPacketCodec.EncryptHeader(datagram, datagram.Length, _headerEnc, Stamp());
            _ = _transport.SendAsync(datagram);
        }

        void HandlePacket(ReadOnlySpan<byte> span)
        {
            if (!_codec.TryDecodePacket(span, _transform, out _, out N2nPacket packet)) return;
            PacketCount++;
            lock (_sync) _clientMac ??= MacAddress.FromBytes(packet.SrcMac);

            byte[]? replyFrame = BuildReply(packet.Payload);
            if (replyFrame is null) return;
            SendFrameToClient(replyFrame);
        }

        // Re-wrap an Ethernet frame as a PACKET addressed to the client and send it over the loopback.
        void SendFrameToClient(byte[] ethernetFrame)
        {
            MacAddress? clientMac;
            lock (_sync) clientMac = _clientMac;
            var body = new N2nPacket
            {
                SrcMac = _gatewayMac.ToArray(),
                DstMac = clientMac?.ToArray() ?? new byte[6],
                Transform = _transform.Id,
                Payload = ethernetFrame,
            };
            byte[] datagram = _codec.EncodePacket(_community, body, _transform);
            // A gateway-edge running -H header-encrypts the PACKET header only (payload stays under the transform).
            if (_headerEnc is not null)
            {
                int headerLen = N2nPacketCodec.PacketHeaderLength(body.Sock is not null, body.Sock?.EncodedSize ?? 0);
                N2nPacketCodec.EncryptHeader(datagram, headerLen, _headerEnc, Stamp());
            }
            _ = _transport.SendAsync(datagram);
        }

        // Returns the frame to send back for an inbound frame (ARP reply / IP echo), or null to drop.
        byte[]? BuildReply(byte[] frame)
        {
            if (frame.Length < EthernetFrame.HeaderLength) return null;
            ushort etherType = EthernetFrame.EtherType(frame);
            if (etherType == EthernetFrame.EtherTypeArp) return BuildArpReply(frame);
            if (etherType == EthernetFrame.EtherTypeIpv4) return BuildIpEcho(frame);
            return null;
        }

        byte[]? BuildArpReply(byte[] frame)
        {
            ReadOnlySpan<byte> arp = EthernetFrame.Payload(frame).Span;
            if (!ArpPacket.IsIpv4OverEthernet(arp) || ArpPacket.Operation(arp) != ArpPacket.OperationRequest) return null;

            MacAddress senderMac = ArpPacket.SenderMac(arp);
            IPAddress senderIp = ArpPacket.SenderIp(arp);
            IPAddress targetIp = ArpPacket.TargetIp(arp);

            // Answer for any in-subnet target with the gateway MAC (proxy-ARP for the gateway/world).
            return EthernetFrame.Build(senderMac, _gatewayMac, EthernetFrame.EtherTypeArp,
                ArpPacket.BuildReply(_gatewayMac, targetIp, senderMac, senderIp));
        }

        // Echo an inbound IPv4 unicast frame back to the client (swap the MACs, keep the payload byte-exact).
        byte[] BuildIpEcho(byte[] frame)
        {
            MacAddress dst = EthernetFrame.Source(frame);   // back to the client
            ReadOnlyMemory<byte> ip = EthernetFrame.Payload(frame);
            return EthernetFrame.Build(dst, _gatewayMac, EthernetFrame.EtherTypeIpv4, ip.Span);
        }

        public void Dispose() { }
    }
}
