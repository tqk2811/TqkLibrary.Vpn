using Microsoft.Extensions.Logging;
using System.Net;
using TqkLibrary.Proxy.Interfaces;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.IpStack.Udp;

namespace Vpn2ProxyDemo
{
    public sealed partial class VpnProxySource
    {
        /// <summary>
        /// The UDP egress channel a SOCKS5 UDP ASSOCIATE relay uses to send/receive datagrams through the VPN tunnel.
        /// The proxy server owns the client-facing UDP socket; this source only carries datagrams out the tunnel to
        /// the real destination and back, via a userspace <see cref="UdpConnection"/> on the tunnel's <see cref="TcpIpStack"/>.
        /// <para>
        /// Because the underlying socket is connection-less (a destination is supplied per <see cref="SendAsync"/> and
        /// reported per <see cref="ReceiveAsync"/>), one source serves every destination the client targets. Dual-stack:
        /// IPv4 and (when the tunnel carries a global IPv6) IPv6 destinations both ride the same userspace UDP socket (P1.1).
        /// </para>
        /// </summary>
        public sealed class VpnUdpAssociateSource : IUdpAssociateSource
        {
            readonly TcpIpStack _stack;
            readonly ILogger? _logger;
            UdpConnection? _socket;
            bool _disposed;

            internal VpnUdpAssociateSource(TcpIpStack stack, ILogger? logger = null)
            {
                _stack = stack;
                _logger = logger;
            }

            /// <inheritdoc/>
            public IPEndPoint? RelayEndPoint { get; private set; }

            /// <inheritdoc/>
            public IPEndPoint? LocalEndPoint { get; private set; }

            /// <inheritdoc/>
            public Task<IPEndPoint> AssociateAsync(CancellationToken cancellationToken = default)
            {
                if (_disposed) throw new ObjectDisposedException(nameof(VpnUdpAssociateSource));
                if (_socket is not null) throw new InvalidOperationException($"{nameof(AssociateAsync)} already called.");

                _socket = _stack.BindUdp();
                // The tunnel stack has no OS socket endpoint; the SOCKS5 server builds the client-facing BND.ADDR itself
                // and never reads these. Report the bound local UDP port for diagnostics.
                LocalEndPoint = new IPEndPoint(IPAddress.Any, _socket.LocalPort);
                RelayEndPoint = LocalEndPoint;
                _logger?.LogInformation("UDP ASSOCIATE — bind cổng UDP {Port} trên tunnel.", _socket.LocalPort);
                return Task.FromResult(RelayEndPoint);
            }

            /// <inheritdoc/>
            public Task SendAsync(IPEndPoint destination, byte[] payload, int offset, int count, CancellationToken cancellationToken = default)
            {
                if (destination is null) throw new ArgumentNullException(nameof(destination));
                if (payload is null) throw new ArgumentNullException(nameof(payload));
                if (offset < 0 || count < 0 || offset + count > payload.Length) throw new ArgumentOutOfRangeException(nameof(count));
                if (_disposed) throw new ObjectDisposedException(nameof(VpnUdpAssociateSource));
                if (_socket is null) throw new InvalidOperationException($"Call {nameof(AssociateAsync)} first.");

                // IPv4 or IPv6: the dual-stack tunnel stack routes the datagram by the destination's family (P1.1).
                _socket.SendTo(destination.Address, (ushort)destination.Port, payload.AsSpan(offset, count));
                _logger?.LogDebug("UDP gửi {Count} byte -> {Destination} qua tunnel.", count, destination);
                return Task.CompletedTask;
            }

            /// <inheritdoc/>
            public async Task<UdpAssociateDatagram> ReceiveAsync(CancellationToken cancellationToken = default)
            {
                if (_disposed) throw new ObjectDisposedException(nameof(VpnUdpAssociateSource));
                if (_socket is null) throw new InvalidOperationException($"Call {nameof(AssociateAsync)} first.");

                var result = await _socket.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                _logger?.LogDebug("UDP nhận {Count} byte <- {Source}:{Port} qua tunnel.", result.Data.Length, result.RemoteAddress, result.RemotePort);
                return new UdpAssociateDatagram(new IPEndPoint(result.RemoteAddress, result.RemotePort), result.Data);
            }

            /// <inheritdoc/>
            public Task<Stream> GetStreamAsync(CancellationToken cancellationToken = default)
                => throw new NotSupportedException("UDP ASSOCIATE source has no stream — use SendAsync/ReceiveAsync.");

            /// <inheritdoc/>
            public void Dispose()
            {
                if (_disposed) return;
                _disposed = true;
                if (_socket is not null)
                {
                    _logger?.LogDebug("UDP ASSOCIATE — gỡ cổng UDP {Port} khỏi tunnel.", _socket.LocalPort);
                    _stack.UnbindUdp(_socket.LocalPort);
                    _socket = null;
                }
            }
        }
    }
}
