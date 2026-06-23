using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using TqkLibrary.VpnClient.OpenVpn;
using TqkLibrary.VpnClient.OpenVpn.Enums;
using TqkLibrary.VpnClient.OpenVpn.Transport;
using TqkLibrary.VpnClient.Transport.Tcp;

namespace TqkLibrary.VpnClient.Drivers.OpenVpn.Transport
{
    /// <summary>
    /// The production <see cref="IOpenVpnTransportFactory"/>: opens a real outer socket. For <see cref="OpenVpnProtocol.Udp"/>
    /// it connects a UDP socket and wraps it in an <see cref="OpenVpnUdpTransport"/> (no framing — one datagram is one
    /// packet); for <see cref="OpenVpnProtocol.Tcp"/> it connects the shared (non-TLS) <see cref="TcpByteStream"/>
    /// (roadmap F.1's <c>Transport.Tcp</c> — OpenVPN runs TLS <em>inside</em> the control channel, not on the transport)
    /// and wraps it in an <see cref="OpenVpnTcpTransport"/> (16-bit length framing). The socket I/O is exercised live
    /// (lab Q.1); the offline tests drive the connection through an in-process factory instead.
    /// </summary>
    public sealed class OpenVpnSocketTransportFactory : IOpenVpnTransportFactory
    {
        readonly OpenVpnProtocol _protocol;

        /// <summary>Creates the factory for the given wire protocol (UDP or TCP).</summary>
        public OpenVpnSocketTransportFactory(OpenVpnProtocol protocol) => _protocol = protocol;

        /// <inheritdoc/>
        public async Task<OpenVpnTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken)
        {
            if (remote is null) throw new ArgumentNullException(nameof(remote));
            if (_protocol == OpenVpnProtocol.Tcp)
            {
                var stream = new TcpByteStream(remote);
                await stream.ConnectAsync(cancellationToken).ConfigureAwait(false);
                var transport = new OpenVpnTcpTransport(stream);
                return new OpenVpnTransportHandle(transport, transport.RunReceiveLoopAsync, stream);
            }
            else
            {
                var socket = new UdpDatagramSocket(remote);
                await socket.ConnectAsync(cancellationToken).ConfigureAwait(false);
                var transport = new OpenVpnUdpTransport(socket);
                return new OpenVpnTransportHandle(transport, transport.RunReceiveLoopAsync, socket);
            }
        }

        /// <summary>A connected UDP datagram pipe over a real socket (live-only; mirrors the TcpByteStream TFM handling).</summary>
        sealed class UdpDatagramSocket : Abstractions.Transport.Interfaces.IDatagramTransport
        {
            // Windows-only ioctl: when false, a UDP send that draws an ICMP "port unreachable" no longer makes the *next*
            // receive/send on the connected socket throw SocketException(ConnectionReset, WSAECONNRESET). Without this the
            // receive loop faults on the first spurious ICMP, the connection reconnects, the socket is disposed, and an
            // in-flight send NREs (UdpClient.Client goes null) inside a timer callback — crashing the process.
            const int SIO_UDP_CONNRESET = unchecked((int)0x9800000C);

            readonly IPEndPoint _remote;
            readonly UdpClient _client;
            readonly Socket _socket;   // captured once so a concurrent dispose can't turn UdpClient.Client into a null deref

            public UdpDatagramSocket(IPEndPoint remote)
            {
                _remote = remote;
                _client = new UdpClient(remote.AddressFamily);
                _socket = _client.Client;
            }

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default)
            {
                _client.Connect(_remote); // sets the default peer; sends/receives are then connection-style
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    // Swallow the ICMP-unreachable → ConnectionReset behaviour (best-effort; not all stacks honour it).
                    try { _socket.IOControl(SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null); } catch { }
                }
                return default;
            }

            public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
            {
#if NET5_0_OR_GREATER
                return new ValueTask(_socket.SendAsync(datagram, SocketFlags.None, cancellationToken).AsTask());
#else
                byte[] copy = datagram.ToArray();
                return new ValueTask(_client.SendAsync(copy, copy.Length)); // connected ⇒ no endpoint
#endif
            }

            public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
#if NET5_0_OR_GREATER
                return await _socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken).ConfigureAwait(false);
#else
                using (cancellationToken.Register(() => { try { _client.Dispose(); } catch { } }))
                {
                    UdpReceiveResult result = await _client.ReceiveAsync().ConfigureAwait(false);
                    cancellationToken.ThrowIfCancellationRequested();
                    int n = Math.Min(result.Buffer.Length, buffer.Length);
                    result.Buffer.AsMemory(0, n).CopyTo(buffer);
                    return n;
                }
#endif
            }

            public ValueTask DisposeAsync()
            {
                try { _client.Dispose(); } catch { }
                return default;
            }
        }
    }
}
