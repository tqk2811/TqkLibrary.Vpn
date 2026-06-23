using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Transport.Tcp
{
    /// <summary>
    /// The shared plain (non-TLS) TCP byte stream behind <see cref="IByteStreamTransport"/>: a <see cref="TcpClient"/>
    /// whose <see cref="NetworkStream"/> is read/written directly. It either resolves <c>host:port</c> (honouring an
    /// <see cref="AddressFamilyPreference"/> so the socket opens in the chosen IPv4/IPv6 family) or connects an
    /// already-resolved <see cref="IPEndPoint"/>.
    /// <para>
    /// This is the transport OpenVPN's <c>proto tcp</c> rides directly (OpenVPN runs TLS <em>inside</em> its control
    /// channel, not on the wire). It is also the layer the TLS byte stream (<c>Transport.Tls</c>) is built on: that wraps
    /// <see cref="Stream"/> in an <see cref="System.Net.Security.SslStream"/> (roadmap F.1). <see cref="ConnectAsync"/>
    /// honours its <see cref="CancellationToken"/> on both target frameworks (native overloads on net8.0;
    /// cancel-by-dispose on netstandard2.0).
    /// </para>
    /// </summary>
    public sealed class TcpByteStream : IByteStreamTransport, IDisposable
    {
        readonly string _host;
        readonly int _port;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly IHostResolver _hostResolver;
        readonly IPEndPoint? _remote;   // when set, the address is already resolved — skip the DNS lookup
        TcpClient? _tcp;
        NetworkStream? _stream;

        /// <summary>
        /// Creates a TCP byte stream to <paramref name="host"/>:<paramref name="port"/> (not yet connected).
        /// <paramref name="addressFamilyPreference"/> selects IPv4/IPv6 when the host resolves to both;
        /// <paramref name="hostResolver"/> performs the name→address lookup (default: DNS).
        /// </summary>
        public TcpByteStream(string host, int port,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto, IHostResolver? hostResolver = null)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _port = port;
            _addressFamilyPreference = addressFamilyPreference;
            _hostResolver = hostResolver ?? DnsHostResolver.Default;
        }

        /// <summary>Creates a TCP byte stream to an already-resolved <paramref name="remote"/> endpoint (not yet connected).</summary>
        public TcpByteStream(IPEndPoint remote)
        {
            _remote = remote ?? throw new ArgumentNullException(nameof(remote));
            _host = remote.Address.ToString();
            _port = remote.Port;
            _hostResolver = DnsHostResolver.Default;
        }

        /// <summary>The host string the stream targets (the TLS layer uses it as the SNI/TargetHost).</summary>
        public string Host => _host;

        /// <summary>The connected stream, exposed so a TLS layer can wrap it; throws until <see cref="ConnectAsync"/> completes.</summary>
        public Stream Stream => _stream ?? throw new InvalidOperationException("The TCP stream is not connected.");

        /// <inheritdoc/>
        public async ValueTask ConnectAsync(CancellationToken cancellationToken = default)
        {
            // Resolve first (unless a concrete endpoint was supplied) so the socket is created in the chosen address
            // family (IPv4/IPv6). The original host string is still used as the TLS TargetHost (SNI) by the TLS layer.
            IPAddress address;
            int port;
            if (_remote is not null) { address = _remote.Address; port = _remote.Port; }
            else
            {
                address = await _hostResolver.ResolveAsync(_host, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
                port = _port;
            }

            var tcp = new TcpClient(address.AddressFamily);
            _tcp = tcp;
#if NET5_0_OR_GREATER
            await tcp.ConnectAsync(address, port, cancellationToken).ConfigureAwait(false);
#else
            // netstandard2.0 TcpClient.ConnectAsync has no CancellationToken overload — cancel by disposing the socket.
            using (cancellationToken.Register(() => { try { tcp.Dispose(); } catch { } }))
            {
                try { await tcp.ConnectAsync(address, port).ConfigureAwait(false); }
                catch (Exception) when (cancellationToken.IsCancellationRequested) { }
            }
            cancellationToken.ThrowIfCancellationRequested();
#endif
            _stream = tcp.GetStream();
        }

        /// <inheritdoc/>
        public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            NetworkStream stream = _stream ?? throw new InvalidOperationException("The TCP stream is not connected.");
#if NET5_0_OR_GREATER
            return await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
#else
            if (MemoryMarshal.TryGetArray<byte>(buffer, out ArraySegment<byte> segment))
                return await stream.ReadAsync(segment.Array!, segment.Offset, segment.Count, cancellationToken).ConfigureAwait(false);
            byte[] temp = new byte[buffer.Length];
            int read = await stream.ReadAsync(temp, 0, temp.Length, cancellationToken).ConfigureAwait(false);
            temp.AsMemory(0, read).CopyTo(buffer);
            return read;
#endif
        }

        /// <inheritdoc/>
        public async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            NetworkStream stream = _stream ?? throw new InvalidOperationException("The TCP stream is not connected.");
#if NET5_0_OR_GREATER
            await stream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
#else
            if (MemoryMarshal.TryGetArray(buffer, out ArraySegment<byte> segment))
                await stream.WriteAsync(segment.Array!, segment.Offset, segment.Count, cancellationToken).ConfigureAwait(false);
            else
            {
                byte[] temp = buffer.ToArray();
                await stream.WriteAsync(temp, 0, temp.Length, cancellationToken).ConfigureAwait(false);
            }
#endif
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            Dispose();
            return default;
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            try { _stream?.Dispose(); } catch { }
            try { _tcp?.Dispose(); } catch { }
        }
    }
}
