using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;

namespace TqkLibrary.VpnClient.OpenVpn.Transport
{
    /// <summary>
    /// tun-mode (<c>dev tun</c>) link bridge: presents the OpenVPN data channel as an L3 <see cref="IPacketChannel"/> so
    /// the userspace TCP/IP stack binds to it directly. The tunnelled payload is a bare IP packet — no MAC, no ARP — so
    /// <see cref="MaxHeaderLength"/> is 0 and <see cref="RequiresLinkAddressResolution"/> is false.
    /// </summary>
    public sealed class OpenVpnTunChannel : OpenVpnDataLink, IPacketChannel
    {
        /// <summary>Wires the tun channel over a data plane + compression codec, sending wire packets to <paramref name="sink"/>.</summary>
        public OpenVpnTunChannel(OpenVpnDataPlane dataPlane, OpenVpnCompression compression, Func<ReadOnlyMemory<byte>, ValueTask> sink, int mtu = 1500)
            : base(dataPlane, compression, sink)
        {
            if (mtu < 1) throw new ArgumentOutOfRangeException(nameof(mtu));
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
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SendPayloadAsync(ipPacket.Span);
        }

        /// <inheritdoc/>
        public override void Deliver(ReadOnlySpan<byte> wire)
        {
            if (TryReceivePayload(wire, out byte[] ipPacket)) InboundIpPacket?.Invoke(ipPacket);
        }
    }
}
