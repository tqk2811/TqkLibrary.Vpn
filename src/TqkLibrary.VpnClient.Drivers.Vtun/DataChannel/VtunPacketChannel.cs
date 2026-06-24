using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Vtun.DataChannel
{
    /// <summary>
    /// The L3 packet channel of an established vtun tun-mode tunnel: a thin <see cref="IPacketChannel"/> that frames each
    /// outbound IP packet as a vtun data frame (via the supplied <c>send</c> sink) and raises <see cref="InboundIpPacket"/>
    /// for each inbound data frame the driver's receive loop hands to <see cref="Deliver"/>. vtun in <c>type tun</c> mode
    /// carries <b>bare IP packets</b> (no link header), so <see cref="Medium"/> is <see cref="LinkMedium.Ip"/> and
    /// <see cref="MaxHeaderLength"/> is 0. Mirrors <c>TincChannel</c> / <c>OpenVpnTunChannel</c>.
    /// </summary>
    public sealed class VtunPacketChannel : IPacketChannel
    {
        readonly Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> _send;
        readonly Action? _onPacketSent;
        readonly Action? _onPacketReceived;

        /// <summary>
        /// Wraps a send sink. <paramref name="send"/> frames and puts an outbound IP packet on the wire (the driver's
        /// data-frame writer). <paramref name="mtu"/> is the tunnel MTU the bound IP stack clamps to.
        /// <paramref name="onPacketSent"/>/<paramref name="onPacketReceived"/> feed the driver's keepalive timers.
        /// </summary>
        public VtunPacketChannel(Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> send,
            int mtu = VtunDriverConstants.DefaultMtu,
            Action? onPacketSent = null,
            Action? onPacketReceived = null)
        {
            _send = send ?? throw new ArgumentNullException(nameof(send));
            if (mtu < 1) throw new ArgumentOutOfRangeException(nameof(mtu));
            Mtu = mtu;
            _onPacketSent = onPacketSent;
            _onPacketReceived = onPacketReceived;
        }

        /// <inheritdoc/>
        public LinkMedium Medium => LinkMedium.Ip;

        /// <inheritdoc/>
        public int Mtu { get; }

        /// <inheritdoc/>
        public int MaxHeaderLength => 0; // vtun tun mode carries bare IP packets — no link header

        /// <inheritdoc/>
        public bool RequiresLinkAddressResolution => false;

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

        /// <inheritdoc/>
        public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
        {
            _onPacketSent?.Invoke();
            return _send(ipPacket, cancellationToken);
        }

        /// <summary>Raises <see cref="InboundIpPacket"/> for an inbound vtun data-frame payload (a bare IP packet).</summary>
        public void Deliver(ReadOnlySpan<byte> ipPacket)
        {
            _onPacketReceived?.Invoke();
            if (ipPacket.Length > 0) InboundIpPacket?.Invoke(ipPacket.ToArray());
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => default;
    }
}
