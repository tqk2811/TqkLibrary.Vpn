using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Tinc.DataChannel
{
    /// <summary>
    /// The L3 packet channel of an established tinc data-plane session: a thin <see cref="IPacketChannel"/> over a
    /// <see cref="TincDataTransport"/>. tinc in <b>router</b> mode carries <b>bare IP packets</b> (no link header), so
    /// <see cref="Medium"/> is <see cref="LinkMedium.Ip"/> and <see cref="MaxHeaderLength"/> is 0.
    /// <para>
    /// <see cref="WriteIpPacketAsync"/> seals the inner IP packet into a UDP data datagram and hands it to the supplied
    /// <c>send</c> sink (the driver's UDP socket); <see cref="Deliver"/> opens an inbound datagram and raises
    /// <see cref="InboundIpPacket"/> with the recovered IP packet. Each outbound seal and each accepted inbound datagram
    /// is reported to the driver (so it can drive its liveness / re-key timers). Mirrors <c>NebulaChannel</c>.
    /// </para>
    /// </summary>
    public sealed class TincChannel : IPacketChannel
    {
        readonly TincDataTransport _transport;
        readonly Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> _send;
        readonly Action? _onPacketSealed;
        readonly Action? _onPacketReceived;

        /// <summary>
        /// Wraps <paramref name="transport"/>. <paramref name="send"/> puts a sealed UDP data datagram on the wire (the
        /// driver's UDP socket). <paramref name="mtu"/> is the tunnel MTU the bound IP stack clamps to.
        /// <paramref name="onPacketSealed"/>/<paramref name="onPacketReceived"/> feed the driver's liveness timers.
        /// </summary>
        public TincChannel(TincDataTransport transport,
            Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> send,
            int mtu = TincDriverConstants.DefaultMtu,
            Action? onPacketSealed = null,
            Action? onPacketReceived = null)
        {
            _transport = transport ?? throw new ArgumentNullException(nameof(transport));
            _send = send ?? throw new ArgumentNullException(nameof(send));
            if (mtu < 1) throw new ArgumentOutOfRangeException(nameof(mtu));
            Mtu = mtu;
            _onPacketSealed = onPacketSealed;
            _onPacketReceived = onPacketReceived;
        }

        /// <summary>The underlying transport (exposed so the driver can read counters for re-key decisions).</summary>
        public TincDataTransport Transport => _transport;

        /// <inheritdoc/>
        public LinkMedium Medium => LinkMedium.Ip;

        /// <inheritdoc/>
        public int Mtu { get; }

        /// <inheritdoc/>
        public int MaxHeaderLength => 0; // tinc router mode carries bare IP packets — no link header

        /// <inheritdoc/>
        public bool RequiresLinkAddressResolution => false;

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

        /// <inheritdoc/>
        public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
        {
            byte[] wire = _transport.Seal(ipPacket.Span); // synchronous: no span crosses the await
            _onPacketSealed?.Invoke();
            return _send(wire, cancellationToken);
        }

        /// <summary>
        /// Opens an inbound UDP data datagram. A data packet is raised on <see cref="InboundIpPacket"/>. Returns
        /// <c>true</c> if the datagram authenticated as a data packet for this session (so the driver can mark the peer
        /// alive), <c>false</c> if it is foreign / forged / replayed / not a data packet.
        /// </summary>
        public bool Deliver(ReadOnlySpan<byte> datagram)
        {
            if (!_transport.TryOpen(datagram, out byte[] inner)) return false;
            _onPacketReceived?.Invoke();
            if (inner.Length > 0) InboundIpPacket?.Invoke(inner);
            return true;
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => default;
    }
}
