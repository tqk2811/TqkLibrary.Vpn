using System.Collections.Concurrent;
using System.Net;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;

namespace TqkLibrary.Vpn.IpStack.Tcp
{
    /// <summary>
    /// Binds an <see cref="IPacketChannel"/> and a local tunnel address, demultiplexes inbound TCP segments to
    /// their connections by local port, and actively opens new TCP connections.
    /// </summary>
    public sealed class TcpIpStack
    {
        readonly IPacketChannel _channel;
        readonly IPAddress _localAddress;
        readonly ConcurrentDictionary<ushort, TcpConnection> _connections = new();
        readonly ConcurrentDictionary<ushort, UdpConnection> _udpSockets = new();
        int _nextPort = 49152;

        /// <summary>Creates the stack over the given channel, sourcing packets from <paramref name="localAddress"/>.</summary>
        public TcpIpStack(IPacketChannel channel, IPAddress localAddress)
        {
            _channel = channel;
            _localAddress = localAddress;
            _channel.InboundIpPacket += OnInbound;
        }

        /// <summary>Opens a TCP connection to <paramref name="remoteAddress"/>:<paramref name="remotePort"/> through the tunnel.</summary>
        public async Task<TcpConnection> ConnectAsync(IPAddress remoteAddress, ushort remotePort, CancellationToken cancellationToken = default)
        {
            ushort localPort = (ushort)Interlocked.Increment(ref _nextPort);
            var connection = new TcpConnection(_localAddress, localPort, remoteAddress, remotePort, SendIp);
            _connections[localPort] = connection;

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

        void SendIp(byte[] ipPacket) => _ = _channel.WriteIpPacketAsync(ipPacket);

        void OnInbound(ReadOnlyMemory<byte> ipPacket)
        {
            ReadOnlySpan<byte> span = ipPacket.Span;
            if (span.Length < 20) return;

            byte protocol = Ipv4.Protocol(span);
            if (protocol == Ipv4.ProtocolTcp)
            {
                ReadOnlyMemory<byte> tcp = Ipv4.Payload(ipPacket);
                if (tcp.Length < 20) return;
                ushort localPort = TcpSegment.DestinationPort(tcp.Span); // our local port (the segment's destination)
                if (_connections.TryGetValue(localPort, out TcpConnection? connection))
                    connection.OnSegment(tcp);
            }
            else if (protocol == Ipv4.ProtocolUdp)
            {
                ReadOnlyMemory<byte> udp = Ipv4.Payload(ipPacket);
                if (udp.Length < 8) return;
                ushort localPort = UdpDatagram.DestinationPort(udp.Span);
                if (_udpSockets.TryGetValue(localPort, out UdpConnection? socket))
                    socket.OnDatagram(Ipv4.Source(span), UdpDatagram.SourcePort(udp.Span), UdpDatagram.Payload(udp).ToArray());
            }
        }
    }
}
