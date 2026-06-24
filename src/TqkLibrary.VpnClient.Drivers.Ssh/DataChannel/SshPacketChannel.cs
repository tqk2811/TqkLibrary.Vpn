using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Ssh.DataChannel
{
    /// <summary>
    /// The L3 packet channel of an established VPN-over-SSH tunnel: a thin <see cref="IPacketChannel"/> that sends each
    /// outbound IP packet over the SSH tun channel (via the supplied <c>send</c> sink — which wraps the tun@openssh.com
    /// AF framing + SSH_MSG_CHANNEL_DATA) and raises <see cref="InboundIpPacket"/> for each inbound IP packet the driver's
    /// receive loop hands to <see cref="Deliver"/>. tun@openssh.com point-to-point carries <b>bare IP packets</b> (the
    /// 4-byte address-family header is stripped/added by the SSH layer), so <see cref="Medium"/> is
    /// <see cref="LinkMedium.Ip"/> and <see cref="MaxHeaderLength"/> is 0. Mirrors <c>VtunPacketChannel</c> /
    /// <c>TincChannel</c>.
    /// </summary>
    public sealed class SshPacketChannel : IPacketChannel
    {
        readonly Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> _send;
        readonly Action? _onPacketSent;
        readonly Action? _onPacketReceived;

        /// <summary>
        /// Wraps a send sink. <paramref name="send"/> puts an outbound IP packet on the SSH tun channel.
        /// <paramref name="mtu"/> is the tunnel MTU the bound IP stack clamps to.
        /// <paramref name="onPacketSent"/>/<paramref name="onPacketReceived"/> feed the driver's keepalive timers.
        /// </summary>
        public SshPacketChannel(Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> send,
            int mtu = SshDriverConstants.DefaultMtu,
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
        public int MaxHeaderLength => 0; // tun@openssh.com L3 carries bare IP packets — no link header

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

        /// <summary>Raises <see cref="InboundIpPacket"/> for an inbound bare IP packet (decapsulated from a tun channel-data frame).</summary>
        public void Deliver(ReadOnlySpan<byte> ipPacket)
        {
            _onPacketReceived?.Invoke();
            if (ipPacket.Length > 0) InboundIpPacket?.Invoke(ipPacket.ToArray());
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => default;
    }
}
