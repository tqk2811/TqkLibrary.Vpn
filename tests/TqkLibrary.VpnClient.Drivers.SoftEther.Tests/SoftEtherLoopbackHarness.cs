using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.SoftEther.Transport;
using TqkLibrary.VpnClient.Ethernet;
using TqkLibrary.VpnClient.Ethernet.Helpers;
using TqkLibrary.VpnClient.SoftEther;
using TqkLibrary.VpnClient.SoftEther.DataChannel;

namespace TqkLibrary.VpnClient.Drivers.SoftEther.Tests
{
    /// <summary>
    /// Offline harness for driving the real <see cref="SoftEtherConnection"/> against an in-process SoftEther server
    /// built from the same protocol blocks (the control PACK codec + the data block codec + the Ethernet/ARP/DHCP codecs).
    /// A lossless in-memory full-duplex byte pipe ties the two together. This is throwaway test scaffolding: the library
    /// is a client, the server (SecureNAT) role exists only here.
    /// </summary>

    /// <summary>
    /// An in-memory <see cref="IByteStreamTransport"/> backed by two byte channels (one per direction). Two of these
    /// wired crosswise form a loopback pipe between the client connection and the simulated server.
    /// </summary>
    sealed class DuplexPipe : IByteStreamTransport
    {
        readonly Channel<byte[]> _inbound;
        readonly Channel<byte[]> _outbound;
        byte[] _readRemainder = Array.Empty<byte>();
        int _readOffset;

        DuplexPipe(Channel<byte[]> inbound, Channel<byte[]> outbound)
        {
            _inbound = inbound;
            _outbound = outbound;
        }

        public static (DuplexPipe client, DuplexPipe server) CreatePair()
        {
            var x = Channel.CreateUnbounded<byte[]>();
            var y = Channel.CreateUnbounded<byte[]>();
            return (new DuplexPipe(x, y), new DuplexPipe(y, x));
        }

        public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

        public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_readOffset >= _readRemainder.Length)
            {
                try { _readRemainder = await _inbound.Reader.ReadAsync(cancellationToken).ConfigureAwait(false); }
                catch (ChannelClosedException) { return 0; }   // peer closed → EOF
                _readOffset = 0;
            }
            int n = Math.Min(buffer.Length, _readRemainder.Length - _readOffset);
            _readRemainder.AsSpan(_readOffset, n).CopyTo(buffer.Span);
            _readOffset += n;
            return n;
        }

        public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            _outbound.Writer.TryWrite(buffer.ToArray());
            return default;
        }

        public ValueTask DisposeAsync()
        {
            _outbound.Writer.TryComplete();
            return default;
        }
    }

    /// <summary>An <see cref="ISoftEtherTransportFactory"/> that hands back a fixed in-process byte pipe (the client end).</summary>
    sealed class InProcessSoftEtherTransportFactory : ISoftEtherTransportFactory
    {
        readonly Func<DuplexPipe> _clientEndFactory;

        /// <summary>Each connect (initial + every reconnect) pulls a fresh client pipe so reconnect tests can re-arm the server.</summary>
        public InProcessSoftEtherTransportFactory(Func<DuplexPipe> clientEndFactory) => _clientEndFactory = clientEndFactory;

        public ValueTask<IByteStreamTransport> ConnectAsync(string host, int port,
            AddressFamilyPreference addressFamilyPreference, CancellationToken cancellationToken)
            => new ValueTask<IByteStreamTransport>(_clientEndFactory());
    }

    /// <summary>
    /// A throwaway SoftEther server (SecureNAT): it completes the control handshake (validates the watermark POST,
    /// replies hello → reads login → replies welcome), then runs the data session — answering DHCP DISCOVER/REQUEST with
    /// an OFFER/ACK that leases <see cref="LeasedAddress"/>, answering ARP requests for the gateway, and echoing inbound
    /// IPv4 unicast frames back (swapping MAC src/dst). Re-implemented from the protocol behavior; no GPL source.
    /// </summary>
    sealed class SimulatedSoftEtherServer
    {
        readonly DuplexPipe _pipe;
        readonly IPAddress _leasedAddress;
        readonly IPAddress _gateway;
        readonly IPAddress _subnetMask;
        readonly IPAddress _dns;
        readonly MacAddress _gatewayMac;
        readonly byte[] _serverRandom;
        readonly bool _rejectLogin;
        readonly uint _rejectErrorCode;
        readonly bool _useEncrypt;
        readonly bool _useCompress;
        readonly bool _enableIpv6;

        // IPv6 SecureNAT roles (only when _enableIpv6): an IPv6 router (RA: autonomous /64 prefix) + DHCPv6 server (DNS).
        static readonly IPAddress RouterLla = IPAddress.Parse("fe80::1");
        static readonly IPAddress PrefixV6 = IPAddress.Parse("2001:db8:5e7e::");
        static readonly IPAddress DnsV6 = IPAddress.Parse("2001:4860:4860::8888");

        IByteStreamTransport _dataTransport;   // the data-session I/O (RC4-wrapped when use_encrypt is on)
        MacAddress _clientMac;
        int _dhcpReplies;
        int _raReplies;

        public SimulatedSoftEtherServer(DuplexPipe pipe,
            IPAddress? leasedAddress = null, IPAddress? gateway = null, IPAddress? dns = null,
            bool rejectLogin = false, uint rejectErrorCode = 0,
            bool useEncrypt = false, bool useCompress = false, bool enableIpv6 = false)
        {
            _pipe = pipe;
            _dataTransport = pipe;
            _leasedAddress = leasedAddress ?? IPAddress.Parse("192.168.30.10");
            _gateway = gateway ?? IPAddress.Parse("192.168.30.1");
            _subnetMask = IPAddress.Parse("255.255.255.0");
            _dns = dns ?? IPAddress.Parse("192.168.30.1");
            _gatewayMac = MacAddress.Parse("5e:00:00:00:00:01");
            _rejectLogin = rejectLogin;
            _rejectErrorCode = rejectErrorCode;
            _useEncrypt = useEncrypt;
            _useCompress = useCompress;
            _enableIpv6 = enableIpv6;
            _serverRandom = new byte[SoftEtherProtocol.RandomSize];
            for (int i = 0; i < _serverRandom.Length; i++) _serverRandom[i] = (byte)(0x10 + i);
        }

        /// <summary>The IP the server's DHCP leases to the client.</summary>
        public IPAddress LeasedAddress => _leasedAddress;

        /// <summary>The /64 IPv6 prefix the server advertises for SLAAC (when IPv6 is enabled).</summary>
        public static IPAddress Ipv6Prefix => PrefixV6;

        /// <summary>How many Router Advertisements the server has sent — a hook proving the IPv6 path ran.</summary>
        public int RouterAdvertisements => _raReplies;

        /// <summary>The gateway MAC the server answers ARP with (the next-hop the client resolves before echoing).</summary>
        public MacAddress GatewayMac => _gatewayMac;

        /// <summary>How many DHCP replies (OFFER + ACK) the server has sent — a test hook proving the lease ran.</summary>
        public int DhcpReplies => _dhcpReplies;

        /// <summary>Runs the whole server: control handshake then the data session, until the pipe closes.</summary>
        public async Task RunAsync(CancellationToken cancellationToken)
        {
            try
            {
                await RunHandshakeAsync(cancellationToken).ConfigureAwait(false);
                if (_rejectLogin) return;   // a rejected login: the client tears down, no data session
                await RunDataSessionAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { }
            catch (SoftEtherProtocolException) { }   // pipe closed mid-read on teardown
        }

        // ---- control handshake (over HTTP/PACK) ----

        async Task RunHandshakeAsync(CancellationToken cancellationToken)
        {
            // 1) watermark POST → reply hello PACK.
            (string head, _) = await ReadHttpMessageAsync(cancellationToken).ConfigureAwait(false);
            if (!head.StartsWith("POST /vpnsvc/connect.cgi", StringComparison.Ordinal))
                throw new SoftEtherProtocolException("server: unexpected watermark target.");
            var hello = new Pack()
                .SetStr("hello", "softether").SetInt("version", 441u).SetInt("build", 9772u)
                .SetData("random", _serverRandom);
            await _pipe.WriteAsync(SoftEtherHttpPackCodec.BuildOkResponse(hello)).ConfigureAwait(false);

            // 2) login POST → reply welcome (or error) PACK.
            (_, byte[] loginBody) = await ReadHttpMessageAsync(cancellationToken).ConfigureAwait(false);
            Pack login = SoftEtherHttpPackCodec.ParseBody(loginBody);
            _ = login.GetStr("username");   // present; the offline server does not re-verify the SHA-0 here

            byte[] sessionKey = NewSessionKey();
            Pack reply = _rejectLogin
                ? new Pack().SetInt("error", _rejectErrorCode)
                : new Pack().SetInt("error", 0u).SetData("session_name", sessionKey);
            await _pipe.WriteAsync(SoftEtherHttpPackCodec.BuildOkResponse(reply)).ConfigureAwait(false);

            // use_encrypt: from here the data session is RC4-encrypted below the framing (the server is the mirror of
            // the client's CreateClient). The handshake above ran in plaintext on the raw pipe.
            if (!_rejectLogin && _useEncrypt)
                _dataTransport = SoftEtherEncryptedTransport.CreateServer(_pipe, sessionKey);
        }

        static byte[] NewSessionKey()
        {
            var key = new byte[20];
            for (int i = 0; i < key.Length; i++) key[i] = (byte)(0xA0 + i);
            return key;
        }

        // ---- data session (Ethernet over the byte stream) ----

        async Task RunDataSessionAsync(CancellationToken cancellationToken)
        {
            var reader = new SoftEtherDataBlockReader(_dataTransport);
            while (!cancellationToken.IsCancellationRequested)
            {
                IReadOnlyList<byte[]> frames = await reader.ReadBlockAsync(cancellationToken).ConfigureAwait(false);
                if (frames.Count == 0) return;   // client closed the pipe
                foreach (byte[] frame in frames)
                    await HandleFrameAsync(frame, cancellationToken).ConfigureAwait(false);
            }
        }

        async Task HandleFrameAsync(byte[] wireFrame, CancellationToken cancellationToken)
        {
            // use_compress: the client compresses a frame before block-encoding it; undo that here (raw frames, e.g. the
            // keep-alive, pass through unchanged because they carry no compression magic).
            byte[] frame = _useCompress ? SoftEtherPayloadCompressor.DecompressFrame(wireFrame) : wireFrame;
            if (SoftEtherDataFrameCodec.IsKeepAlive(frame)) return;       // client keep-alive — ignore
            if (frame.Length < EthernetFrame.HeaderLength) return;

            // Build the reply synchronously (the span-using codecs cannot live in an async method, C# 12); send it here.
            byte[]? reply = BuildReply(frame);
            if (reply != null)
                await SendFrameAsync(reply, cancellationToken).ConfigureAwait(false);
        }

        // Returns the frame to send back for an inbound frame (ARP reply / DHCP OFFER-ACK / IP echo), or null to drop.
        byte[]? BuildReply(byte[] frame)
        {
            ushort etherType = EthernetFrame.EtherType(frame);
            _clientMac = EthernetFrame.Source(frame);

            if (etherType == EthernetFrame.EtherTypeArp)
                return BuildArpReply(frame);
            if (etherType == EthernetFrame.EtherTypeIpv4)
            {
                ReadOnlyMemory<byte> ip = EthernetFrame.Payload(frame);
                if (TryReadDhcpRequest(ip, out ReadOnlyMemory<byte> dhcp))
                    return BuildDhcpReplyFrame(dhcp);
                return BuildIpEcho(frame);   // an ordinary IPv4 unicast → echo back
            }
            if (etherType == EthernetFrame.EtherTypeIpv6 && _enableIpv6)
                return BuildIpv6Reply(frame);
            return null;
        }

        // IPv6 SecureNAT: answer NDISC (RS→RA, NS→NA) and DHCPv6 (SOLICIT→ADVERTISE, REQUEST→REPLY), echo other unicast.
        byte[]? BuildIpv6Reply(byte[] frame)
        {
            ReadOnlyMemory<byte> ip = EthernetFrame.Payload(frame);
            ReadOnlySpan<byte> p = ip.Span;
            if (p.Length < 40 || (byte)(p[0] >> 4) != 6)
                return null;

            byte nextHeader = p[6];
            if (nextHeader == Icmpv6Ndisc.ProtocolNumber)   // ICMPv6 (NDISC)
            {
                ReadOnlySpan<byte> message = p.Slice(40);
                if (!Icmpv6Ndisc.IsNdisc(message))
                    return null;
                byte type = Icmpv6Ndisc.Type(message);
                if (type == Icmpv6Ndisc.TypeRouterSolicitation)
                    return BuildRaFrame();
                if (type == Icmpv6Ndisc.TypeNeighborSolicitation)
                    return BuildNaFrame(message);   // answer for the router/gateway address the client is resolving
                return null;
            }
            if (nextHeader == 17 && p.Length >= 40 + 8 && ((p[40 + 2] << 8) | p[40 + 3]) == Dhcpv6Packet.ServerPort)
            {
                ReadOnlySpan<byte> dhcp = p.Slice(40 + 8);
                uint xid = Dhcpv6Packet.TransactionId(dhcp);
                byte type = Dhcpv6Packet.MessageType(dhcp);
                byte reply = type == Dhcpv6Packet.MessageSolicit ? Dhcpv6Packet.MessageAdvertise
                    : type == Dhcpv6Packet.MessageRequest ? Dhcpv6Packet.MessageReply : (byte)0;
                if (reply == 0)
                    return null;
                return BuildDhcpV6ReplyFrame(reply, xid);
            }
            return BuildIpv6Echo(frame);   // an ordinary IPv6 unicast → echo back
        }

        byte[] BuildRaFrame()
        {
            _raReplies++;
            byte prefixFlags = (byte)(Icmpv6Ndisc.PrefixFlagOnLink | Icmpv6Ndisc.PrefixFlagAutonomous);
            byte[] ra = Icmpv6Ndisc.BuildRouterAdvertisement(RouterLla, Icmpv6Ndisc.AllNodes, _gatewayMac,
                curHopLimit: 64, routerLifetimeSeconds: 1800,
                prefix: PrefixV6, prefixLength: 64, prefixFlags: prefixFlags,
                validLifetime: 86400, preferredLifetime: 14400);
            ra[5] = Icmpv6Ndisc.RaFlagOther;   // O flag: SLAAC forms the address, DHCPv6 brings DNS (no M → no stateful address)
            byte[] ipv6 = Icmpv6Ndisc.BuildIpv6(RouterLla, Icmpv6Ndisc.AllNodes, ra);
            return EthernetFrame.Build(Icmpv6Ndisc.MulticastMac(Icmpv6Ndisc.AllNodes), _gatewayMac, EthernetFrame.EtherTypeIpv6, ipv6);
        }

        byte[]? BuildNaFrame(ReadOnlySpan<byte> nsMessage)
        {
            IPAddress target = Icmpv6Ndisc.TargetAddress(nsMessage);   // the address the client wants the MAC of
            // SecureNAT proxies the world: answer any solicitation with the gateway MAC (like proxy-ARP for v4).
            byte[] na = Icmpv6Ndisc.BuildNeighborAdvertisement(target, _clientLla(), target, _gatewayMac,
                (byte)(Icmpv6Ndisc.FlagSolicited | Icmpv6Ndisc.FlagOverride));
            byte[] ipv6 = Icmpv6Ndisc.BuildIpv6(target, _clientLla(), na);
            return EthernetFrame.Build(_clientMac, _gatewayMac, EthernetFrame.EtherTypeIpv6, ipv6);
        }

        byte[] BuildDhcpV6ReplyFrame(byte messageType, uint xid)
        {
            byte[] serverDuid = Dhcpv6Options.BuildDuidLinkLayer(_gatewayMac);
            byte[] clientDuid = Dhcpv6Options.BuildDuidLinkLayer(_clientMac);
            byte[] options = new byte[256];
            int pos = Dhcpv6Options.WriteOption(options, 0, Dhcpv6Options.CodeServerId, serverDuid);
            pos = Dhcpv6Options.WriteOption(options, pos, Dhcpv6Options.CodeClientId, clientDuid);
            pos = Dhcpv6Options.WriteOption(options, pos, Dhcpv6Options.CodeDnsServers, DnsV6.GetAddressBytes());
            byte[] dhcp = Dhcpv6Packet.Build(messageType, xid, options.AsSpan(0, pos));
            byte[] udpIp = Dhcpv6Packet.BuildUdpIpv6(RouterLla, _clientLla(),
                Dhcpv6Packet.ServerPort, Dhcpv6Packet.ClientPort, dhcp);
            return EthernetFrame.Build(_clientMac, _gatewayMac, EthernetFrame.EtherTypeIpv6, udpIp);
        }

        // The client's link-local address (fe80::/64 + Modified EUI-64 of its MAC) — destination of unicast NA/DHCPv6.
        IPAddress _clientLla()
            => SlaacAddress.Combine(IPAddress.Parse("fe80::"), 64, SlaacAddress.ModifiedEui64(_clientMac));

        // Echo an inbound IPv6 unicast frame back to the client (swap the MACs, keep the payload byte-exact).
        byte[] BuildIpv6Echo(byte[] frame)
        {
            MacAddress src = EthernetFrame.Source(frame);
            ReadOnlyMemory<byte> ip = EthernetFrame.Payload(frame);
            return EthernetFrame.Build(src, _gatewayMac, EthernetFrame.EtherTypeIpv6, ip.Span);
        }

        // Server-side DHCP detection: extract the DHCP message from a UDP/IPv4 packet addressed to the server port (67).
        // (DhcpV4Packet.TryReadUdpIpv4 only matches the client port 68 — that is the client's receive path.)
        static bool TryReadDhcpRequest(ReadOnlyMemory<byte> packet, out ReadOnlyMemory<byte> dhcpMessage)
        {
            dhcpMessage = default;
            ReadOnlySpan<byte> span = packet.Span;
            if (span.Length < 28 || (byte)(span[0] >> 4) != 4) return false;
            int ihl = (span[0] & 0x0F) * 4;
            if (ihl < 20 || span.Length < ihl + 8 || span[9] != 17) return false;   // IPv4 + UDP
            int udp = ihl;
            int destPort = (span[udp + 2] << 8) | span[udp + 3];
            if (destPort != DhcpV4Packet.ServerPort) return false;                   // not addressed to the DHCP server port
            int udpLength = (span[udp + 4] << 8) | span[udp + 5];
            if (udpLength < 8 || udp + udpLength > span.Length) return false;
            dhcpMessage = packet.Slice(udp + 8, udpLength - 8);
            return true;
        }

        byte[]? BuildArpReply(byte[] frame)
        {
            ReadOnlySpan<byte> arp = EthernetFrame.Payload(frame).Span;
            if (!ArpPacket.IsIpv4OverEthernet(arp) || ArpPacket.Operation(arp) != ArpPacket.OperationRequest) return null;

            MacAddress senderMac = ArpPacket.SenderMac(arp);
            IPAddress senderIp = ArpPacket.SenderIp(arp);
            IPAddress targetIp = ArpPacket.TargetIp(arp);

            // Answer for any in-subnet target with the gateway MAC (SecureNAT proxy-ARPs the world).
            return EthernetFrame.Build(senderMac, _gatewayMac, EthernetFrame.EtherTypeArp,
                ArpPacket.BuildReply(_gatewayMac, targetIp, senderMac, senderIp));
        }

        byte[]? BuildDhcpReplyFrame(ReadOnlyMemory<byte> dhcp)
        {
            byte type = DhcpV4Options.ReadMessageType(DhcpV4Packet.OptionField(dhcp).Span);
            byte replyType =
                type == DhcpV4Options.MessageDiscover ? DhcpV4Options.MessageOffer :
                type == DhcpV4Options.MessageRequest ? DhcpV4Options.MessageAck : (byte)0;
            if (replyType == 0) return null;

            uint xid = DhcpV4Packet.Xid(dhcp.Span);
            _dhcpReplies++;
            return BuildDhcpReply(xid, replyType);
        }

        byte[] BuildDhcpReply(uint xid, byte messageType)
        {
            // Server-side DHCP reply: yiaddr = leased address, options message-type/server-id/mask/router/dns/lease.
            var opt = new byte[128];
            int pos = DhcpV4Options.WriteMagicCookie(opt, 0);
            pos = DhcpV4Options.WriteOption(opt, pos, DhcpV4Options.CodeMessageType, messageType);
            pos = DhcpV4Options.WriteOption(opt, pos, DhcpV4Options.CodeServerId, _gateway);
            pos = DhcpV4Options.WriteOption(opt, pos, DhcpV4Options.CodeSubnetMask, _subnetMask);
            pos = DhcpV4Options.WriteOption(opt, pos, DhcpV4Options.CodeRouter, _gateway);
            pos = DhcpV4Options.WriteOption(opt, pos, DhcpV4Options.CodeDnsServer, _dns);
            pos = DhcpV4Options.WriteOption(opt, pos, DhcpV4Options.CodeLeaseTime, new byte[] { 0, 0, 0x0E, 0x10 }); // 3600s
            pos = DhcpV4Options.WriteEnd(opt, pos);

            byte[] message = BuildBootReply(xid, _leasedAddress, _gateway, _clientMac, opt.AsSpan(0, pos));
            byte[] udpIp = DhcpV4Packet.BuildUdpIpv4(_gateway, IPAddress.Broadcast,
                DhcpV4Packet.ServerPort, DhcpV4Packet.ClientPort, message);
            return EthernetFrame.Build(_clientMac, _gatewayMac, EthernetFrame.EtherTypeIpv4, udpIp);
        }

        // A BOOTREPLY: op=2, yiaddr set, chaddr = client MAC, then the option field.
        static byte[] BuildBootReply(uint xid, IPAddress yiaddr, IPAddress siaddr, MacAddress clientMac, ReadOnlySpan<byte> options)
        {
            byte[] message = new byte[DhcpV4Packet.HeaderLength + options.Length];
            message[0] = DhcpV4Packet.OpBootReply;
            message[1] = DhcpV4Packet.HardwareTypeEthernet;
            message[2] = DhcpV4Packet.HardwareAddressLength;
            message[4] = (byte)(xid >> 24); message[5] = (byte)(xid >> 16); message[6] = (byte)(xid >> 8); message[7] = (byte)xid;
            yiaddr.GetAddressBytes().CopyTo(message, 16);   // yiaddr
            siaddr.GetAddressBytes().CopyTo(message, 20);   // siaddr
            clientMac.CopyTo(message.AsSpan(28, MacAddress.Size));   // chaddr
            options.CopyTo(message.AsSpan(DhcpV4Packet.HeaderLength));
            return message;
        }

        // Echo an inbound IPv4 unicast frame back to the client (swap the MACs, keep the payload byte-exact).
        byte[] BuildIpEcho(byte[] frame)
        {
            MacAddress src = EthernetFrame.Source(frame);
            ReadOnlyMemory<byte> ip = EthernetFrame.Payload(frame);
            return EthernetFrame.Build(src, _gatewayMac, EthernetFrame.EtherTypeIpv4, ip.Span);
        }

        ValueTask SendFrameAsync(byte[] frame, CancellationToken cancellationToken)
        {
            // Mirror the client: compress before block-encoding (when use_compress) and write to the RC4-wrapped
            // data transport (when use_encrypt).
            ReadOnlyMemory<byte> payload = _useCompress ? SoftEtherPayloadCompressor.CompressFrame(frame) : frame;
            return _dataTransport.WriteAsync(SoftEtherDataFrameCodec.EncodeSingle(payload), cancellationToken);
        }

        // ---- minimal HTTP reader (mirrors the SoftEther.Tests stub server) ----

        async Task<(string head, byte[] body)> ReadHttpMessageAsync(CancellationToken cancellationToken)
        {
            var buffer = new List<byte>();
            int headerEnd = -1;
            var chunk = new byte[1024];
            while (headerEnd < 0)
            {
                int n = await _pipe.ReadAsync(chunk, cancellationToken).ConfigureAwait(false);
                if (n == 0) throw new SoftEtherProtocolException("server: stream closed before headers.");
                for (int i = 0; i < n; i++) buffer.Add(chunk[i]);
                headerEnd = FindHeaderEnd(buffer);
            }
            string head = Encoding.ASCII.GetString(buffer.ToArray(), 0, headerEnd);
            int contentLength = ParseContentLength(head);
            int bodyStart = headerEnd + 4;
            var body = new byte[contentLength];
            int have = Math.Min(contentLength, buffer.Count - bodyStart);
            for (int i = 0; i < have; i++) body[i] = buffer[bodyStart + i];
            int filled = have;
            while (filled < contentLength)
            {
                int n = await _pipe.ReadAsync(new Memory<byte>(body, filled, contentLength - filled), cancellationToken).ConfigureAwait(false);
                if (n == 0) throw new SoftEtherProtocolException("server: stream closed before body.");
                filled += n;
            }
            return (head, body);
        }

        static int FindHeaderEnd(List<byte> buffer)
        {
            for (int i = 0; i + 3 < buffer.Count; i++)
                if (buffer[i] == '\r' && buffer[i + 1] == '\n' && buffer[i + 2] == '\r' && buffer[i + 3] == '\n')
                    return i;
            return -1;
        }

        static int ParseContentLength(string head)
        {
            foreach (string line in head.Split(new[] { "\r\n" }, StringSplitOptions.None))
            {
                int c = line.IndexOf(':');
                if (c < 0) continue;
                if (line.Substring(0, c).Trim().Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                    return int.Parse(line.Substring(c + 1).Trim());
            }
            throw new SoftEtherProtocolException("server: no Content-Length.");
        }
    }
}
