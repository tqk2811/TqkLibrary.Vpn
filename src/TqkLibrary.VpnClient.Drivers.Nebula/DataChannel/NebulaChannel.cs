using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Nebula.DataChannel
{
    /// <summary>
    /// The L3 packet channel of one established Nebula session: a thin <see cref="IPacketChannel"/> over a
    /// <see cref="NebulaTransport"/>. Nebula carries <b>bare IP packets</b> (no link header), so <see cref="Medium"/>
    /// is <see cref="LinkMedium.Ip"/> and <see cref="MaxHeaderLength"/> is 0.
    /// <para>
    /// <see cref="WriteIpPacketAsync"/> seals the inner IP packet into a <c>Message</c> (type-1) datagram and hands it
    /// to the supplied <c>send</c> sink (the driver's UDP socket); <see cref="Deliver"/> opens an inbound type-1
    /// datagram and raises <see cref="InboundIpPacket"/> with the recovered IP packet. Each outbound seal and each
    /// accepted inbound datagram is reported to the driver (so it can drive its liveness / re-handshake timers).
    /// </para>
    /// <para>
    /// One channel wraps one transport (one key generation). A re-handshake installs a fresh transport behind a
    /// <see cref="SwappablePacketChannel"/> at the driver level (make-before-break), so this type never mutates its
    /// keys in place — it is replaced wholesale.
    /// </para>
    /// </summary>
    public sealed class NebulaChannel : IPacketChannel
    {
        readonly NebulaTransport _transport;
        readonly Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> _send;
        readonly Action? _onPacketSealed;
        readonly Action? _onPacketReceived;

        /// <summary>
        /// Wraps <paramref name="transport"/>. <paramref name="send"/> puts a sealed type-1 datagram on the wire (the
        /// driver's UDP socket). <paramref name="mtu"/> is the tunnel MTU the bound IP stack clamps to.
        /// <paramref name="onPacketSealed"/> fires after every outbound seal and <paramref name="onPacketReceived"/>
        /// after every accepted inbound message packet — the driver uses them to feed its liveness/re-handshake timers.
        /// </summary>
        public NebulaChannel(NebulaTransport transport,
            Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> send,
            int mtu = NebulaDriverConstants.DefaultMtu,
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

        /// <summary>The underlying transport (exposed so the driver can read counters for re-handshake decisions).</summary>
        public NebulaTransport Transport => _transport;

        /// <inheritdoc/>
        public LinkMedium Medium => LinkMedium.Ip;

        /// <inheritdoc/>
        public int Mtu { get; }

        /// <inheritdoc/>
        public int MaxHeaderLength => 0; // Nebula transport carries bare IP packets — no link header

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
        /// Opens an inbound type-1 message datagram. A data packet is raised on <see cref="InboundIpPacket"/>. Returns
        /// <c>true</c> if the datagram authenticated as a message for this session (so the driver can mark the peer
        /// alive), <c>false</c> if it is foreign / forged / replayed.
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
