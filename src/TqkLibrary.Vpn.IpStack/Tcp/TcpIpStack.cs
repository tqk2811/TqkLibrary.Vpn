using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.IpStack.Tcp.Enums;

namespace TqkLibrary.Vpn.IpStack.Tcp
{
    /// <summary>
    /// Binds an <see cref="IPacketChannel"/> and a local tunnel address, demultiplexes inbound TCP/UDP/ICMP packets
    /// to their connections by local port (echo by identifier for ICMP), and actively opens new TCP connections.
    /// </summary>
    public sealed class TcpIpStack
    {
        static readonly byte[] DefaultPingData = System.Text.Encoding.ASCII.GetBytes("abcdefghijklmnopqrstuvwabcdefghi");

        readonly IPacketChannel _channel;
        readonly IPAddress _localAddress;
        readonly ConcurrentDictionary<ushort, TcpConnection> _connections = new();
        readonly ConcurrentDictionary<ushort, UdpConnection> _udpSockets = new();
        readonly ConcurrentDictionary<ushort, TaskCompletionSource<PingReply>> _pings = new();
        readonly Ipv4Reassembler _reassembler = new();
        readonly ushort _pingIdentifier;
        int _nextPort = 49152;
        int _nextPingSequence;
        int _replyIpId;

        /// <summary>Creates the stack over the given channel, sourcing packets from <paramref name="localAddress"/>.</summary>
        public TcpIpStack(IPacketChannel channel, IPAddress localAddress)
        {
            _channel = channel;
            _localAddress = localAddress;
            byte[] id = new byte[2];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(id);
            _pingIdentifier = (ushort)((id[0] << 8) | id[1]);
            _channel.InboundIpPacket += OnInbound;
        }

        /// <summary>Opens a TCP connection to <paramref name="remoteAddress"/>:<paramref name="remotePort"/> through the tunnel.</summary>
        public async Task<TcpConnection> ConnectAsync(IPAddress remoteAddress, ushort remotePort, CancellationToken cancellationToken = default)
        {
            ushort localPort = (ushort)Interlocked.Increment(ref _nextPort);
            var connection = new TcpConnection(_localAddress, localPort, remoteAddress, remotePort, SendIp);
            _connections[localPort] = connection;
            connection.Closed += () => { _connections.TryRemove(localPort, out _); connection.Dispose(); }; // drop faulted connections (RST / RTO give-up)

            connection.StartConnect();

            Task completed = await Task.WhenAny(connection.Connected, Task.Delay(Timeout.Infinite, cancellationToken)).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            await connection.Connected.ConfigureAwait(false); // observe handshake result/fault
            return connection;
        }

        /// <summary>Binds a userspace UDP socket on an ephemeral local port for datagrams through the tunnel.</summary>
        public UdpConnection BindUdp() => BindUdp((ushort)Interlocked.Increment(ref _nextPort));

        /// <summary>Binds a userspace UDP socket on a specific local port.</summary>
        public UdpConnection BindUdp(ushort localPort)
        {
            var socket = new UdpConnection(_localAddress, localPort, SendIp);
            _udpSockets[localPort] = socket;
            return socket;
        }

        /// <summary>
        /// Sends an ICMP Echo Request through the tunnel and awaits the matching Echo Reply. Throws
        /// <see cref="IcmpUnreachableException"/> if the target replies Destination Unreachable, or
        /// <see cref="OperationCanceledException"/> if cancelled before a reply arrives.
        /// </summary>
        public async Task<PingReply> PingAsync(IPAddress remoteAddress, ReadOnlyMemory<byte> data = default, CancellationToken cancellationToken = default)
        {
            var waiter = new TaskCompletionSource<PingReply>(TaskCreationOptions.RunContinuationsAsynchronously);
            ushort sequence;
            do { sequence = (ushort)Interlocked.Increment(ref _nextPingSequence); } // skip sequences with a ping still
            while (!_pings.TryAdd(sequence, waiter));                               // pending after a 65536-wrap
            try
            {
                ReadOnlySpan<byte> payload = data.IsEmpty ? DefaultPingData : data.Span;
                byte[] icmp = Icmpv4.BuildEcho(Icmpv4.TypeEchoRequest, _pingIdentifier, sequence, payload);
                byte[] ip = Ipv4.Build(_localAddress, remoteAddress, Ipv4.ProtocolIcmp, icmp, (ushort)Interlocked.Increment(ref _replyIpId));

                var stopwatch = Stopwatch.StartNew();
                SendIp(ip);
                using (cancellationToken.Register(static w => ((TaskCompletionSource<PingReply>)w!).TrySetCanceled(), waiter))
                {
                    PingReply reply = await waiter.Task.ConfigureAwait(false);
                    return new PingReply(reply.RemoteAddress, stopwatch.Elapsed, reply.Data);
                }
            }
            finally
            {
                _pings.TryRemove(sequence, out _);
            }
        }

        void SendIp(byte[] ipPacket)
        {
            // Single egress chokepoint: oversized datagrams (large UDP/ICMP) are fragmented to the link MTU (RFC 791)
            // instead of being sent with DF set and silently dropped. TCP segments stay under MSS, so they pass through.
            int mtu = _channel.Mtu;
            if (ipPacket.Length <= mtu)
            {
                _ = _channel.WriteIpPacketAsync(ipPacket);
                return;
            }
            foreach (byte[] fragment in Ipv4.Fragment(ipPacket, mtu))
                _ = _channel.WriteIpPacketAsync(fragment);
        }

        void OnInbound(ReadOnlyMemory<byte> ipPacket)
        {
            if (ipPacket.Length < 20) return;

            // Reassemble fragmented datagrams (RFC 791): whole packets pass through, fragments buffer until complete.
            ReadOnlyMemory<byte>? assembled = _reassembler.Offer(ipPacket);
            if (assembled is null) return;
            ipPacket = assembled.Value;

            ReadOnlySpan<byte> span = ipPacket.Span;
            byte protocol = Ipv4.Protocol(span);
            if (protocol == Ipv4.ProtocolTcp)
            {
                ReadOnlyMemory<byte> tcp = Ipv4.Payload(ipPacket);
                if (tcp.Length < 20) return;
                ushort localPort = TcpSegment.DestinationPort(tcp.Span); // our local port (the segment's destination)
                if (_connections.TryGetValue(localPort, out TcpConnection? connection))
                    connection.OnSegment(tcp);
                else
                    SendTcpReset(Ipv4.Source(span), Ipv4.Destination(span), tcp.Span); // no socket here → RST (RFC 793)
            }
            else if (protocol == Ipv4.ProtocolUdp)
            {
                ReadOnlyMemory<byte> udp = Ipv4.Payload(ipPacket);
                if (udp.Length < 8) return;
                ushort localPort = UdpDatagram.DestinationPort(udp.Span);
                if (_udpSockets.TryGetValue(localPort, out UdpConnection? socket))
                    socket.OnDatagram(Ipv4.Source(span), UdpDatagram.SourcePort(udp.Span), UdpDatagram.Payload(udp).ToArray());
                else
                    SendPortUnreachable(span); // no socket here → ICMP port unreachable (RFC 792 / RFC 1122 §3.2.2.1)
            }
            else if (protocol == Ipv4.ProtocolIcmp)
            {
                ReadOnlyMemory<byte> icmp = Ipv4.Payload(ipPacket);
                if (icmp.Length < Icmpv4.HeaderSize) return;
                OnIcmp(Ipv4.Source(span), icmp);
            }
        }

        void OnIcmp(IPAddress source, ReadOnlyMemory<byte> icmp)
        {
            ReadOnlySpan<byte> span = icmp.Span;
            switch (Icmpv4.Type(span))
            {
                case Icmpv4.TypeEchoRequest:
                {
                    // Answer pings aimed at this tunnel host: echo the payload back with the same identifier/sequence.
                    byte[] reply = Icmpv4.BuildEcho(Icmpv4.TypeEchoReply, Icmpv4.Identifier(span), Icmpv4.Sequence(span), Icmpv4.Payload(icmp).Span);
                    byte[] ip = Ipv4.Build(_localAddress, source, Ipv4.ProtocolIcmp, reply, (ushort)Interlocked.Increment(ref _replyIpId));
                    SendIp(ip);
                    break;
                }
                case Icmpv4.TypeEchoReply:
                {
                    if (Icmpv4.Identifier(span) != _pingIdentifier) break;
                    if (_pings.TryGetValue(Icmpv4.Sequence(span), out TaskCompletionSource<PingReply>? waiter))
                        waiter.TrySetResult(new PingReply(source, TimeSpan.Zero, Icmpv4.Payload(icmp).ToArray()));
                    break;
                }
                case Icmpv4.TypeDestinationUnreachable:
                {
                    // The error quotes our offending datagram: original IP header + first 8 bytes (the Echo Request).
                    ReadOnlySpan<byte> quoted = Icmpv4.Payload(icmp).Span;
                    if (quoted.Length < 20) break;
                    int ihl = (quoted[0] & 0x0F) * 4;
                    if (quoted[9] != Ipv4.ProtocolIcmp || quoted.Length < ihl + Icmpv4.HeaderSize) break;
                    ushort id = (ushort)((quoted[ihl + 4] << 8) | quoted[ihl + 5]);
                    if (id != _pingIdentifier) break;
                    ushort sequence = (ushort)((quoted[ihl + 6] << 8) | quoted[ihl + 7]);
                    if (_pings.TryGetValue(sequence, out TaskCompletionSource<PingReply>? waiter))
                        waiter.TrySetException(new IcmpUnreachableException(Icmpv4.Code(span)));
                    break;
                }
            }
        }

        /// <summary>
        /// Answers an inbound TCP segment aimed at a local port with no connection by sending a RST (RFC 793 p.36):
        /// the peer learns the port is dead instead of retransmitting into the void. A RST is never sent in reply to a
        /// RST, which would otherwise loop into a reset storm.
        /// </summary>
        void SendTcpReset(IPAddress remote, IPAddress local, ReadOnlySpan<byte> segment)
        {
            TcpFlags flags = TcpSegment.Flags(segment);
            if ((flags & TcpFlags.Rst) != 0) return;

            uint sequence, acknowledgment;
            TcpFlags rstFlags;
            if ((flags & TcpFlags.Ack) != 0)
            {
                // The segment carries an ACK: the RST borrows its sequence and acknowledges nothing of its own.
                sequence = TcpSegment.Acknowledgment(segment);
                acknowledgment = 0;
                rstFlags = TcpFlags.Rst;
            }
            else
            {
                // No ACK to borrow: RST sequence 0, ACK the sequence span the segment consumed (SYN/FIN each count 1).
                int dataLength = Math.Max(0, segment.Length - TcpSegment.DataOffset(segment));
                uint segmentLength = (uint)dataLength
                    + (((flags & TcpFlags.Syn) != 0) ? 1u : 0u)
                    + (((flags & TcpFlags.Fin) != 0) ? 1u : 0u);
                sequence = 0;
                acknowledgment = TcpSegment.Sequence(segment) + segmentLength;
                rstFlags = TcpFlags.Rst | TcpFlags.Ack;
            }

            ushort localPort = TcpSegment.DestinationPort(segment); // our port (the segment's destination)
            ushort remotePort = TcpSegment.SourcePort(segment);
            byte[] reset = TcpSegment.Build(local, remote, localPort, remotePort, sequence, acknowledgment, rstFlags, window: 0, ReadOnlySpan<byte>.Empty);
            SendIp(Ipv4.Build(local, remote, Ipv4.ProtocolTcp, reset, (ushort)Interlocked.Increment(ref _replyIpId)));
        }

        /// <summary>
        /// Answers an inbound UDP datagram aimed at a local port with no socket by sending an ICMP Destination
        /// Unreachable / Port Unreachable that quotes the offending datagram (RFC 792, RFC 1122 §3.2.2.1).
        /// </summary>
        void SendPortUnreachable(ReadOnlySpan<byte> offendingIpPacket)
        {
            IPAddress remote = Ipv4.Source(offendingIpPacket);
            IPAddress local = Ipv4.Destination(offendingIpPacket);
            byte[] icmp = Icmpv4.BuildDestinationUnreachable(Icmpv4.CodePortUnreachable, offendingIpPacket);
            SendIp(Ipv4.Build(local, remote, Ipv4.ProtocolIcmp, icmp, (ushort)Interlocked.Increment(ref _replyIpId)));
        }
    }
}
