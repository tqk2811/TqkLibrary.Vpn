using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;

namespace TqkLibrary.VpnClient.Ppp
{
    /// <summary>
    /// The <see cref="IPacketChannel"/> a <see cref="PppEngine"/> exposes once IPCP is up: writes go out as
    /// PPP IP frames; inbound IP frames are raised here. An L3 channel, so no Ethernet header/ARP.
    /// </summary>
    public sealed class PppPacketChannel : IPacketChannel
    {
        readonly Func<ReadOnlyMemory<byte>, ValueTask> _writeIp;

        internal PppPacketChannel(Func<ReadOnlyMemory<byte>, ValueTask> writeIp, int mtu)
        {
            _writeIp = writeIp;
            Mtu = mtu;
        }

        /// <inheritdoc/>
        public LinkMedium Medium => LinkMedium.Ip;

        /// <inheritdoc/>
        public int Mtu { get; }

        /// <inheritdoc/>
        public int MaxHeaderLength => 0;

        /// <inheritdoc/>
        public bool RequiresLinkAddressResolution => false;

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

        /// <inheritdoc/>
        public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
            => _writeIp(ipPacket);

        internal void RaiseInbound(ReadOnlyMemory<byte> packet) => InboundIpPacket?.Invoke(packet);

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => default;
    }
}
