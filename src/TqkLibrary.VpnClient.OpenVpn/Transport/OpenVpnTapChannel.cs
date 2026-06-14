using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;

namespace TqkLibrary.VpnClient.OpenVpn.Transport
{
    /// <summary>
    /// tap-mode (<c>dev tap</c>) link bridge: presents the OpenVPN data channel as an L2 <see cref="IEthernetChannel"/>
    /// so it plugs into the Ethernet fabric (ARP + DHCP + switch), which then bridges down to the IP stack — the stack
    /// never binds here directly. The tunnelled payload is a full Ethernet frame, so <see cref="MaxHeaderLength"/> is 14
    /// and <see cref="RequiresLinkAddressResolution"/> is true. The data-channel wire format is identical to tun mode;
    /// only the payload contents and the channel medium differ.
    /// </summary>
    public sealed class OpenVpnTapChannel : OpenVpnDataLink, IEthernetChannel
    {
        const int EthernetHeaderLength = 14;
        const int MacAddressLength = 6;

        readonly ReadOnlyMemory<byte> _macAddress;

        /// <summary>Wires the tap channel; <paramref name="macAddress"/> is this endpoint's 6-byte MAC.</summary>
        public OpenVpnTapChannel(OpenVpnDataPlane dataPlane, OpenVpnCompression compression, Func<ReadOnlyMemory<byte>, ValueTask> sink, ReadOnlyMemory<byte> macAddress, int mtu = 1500)
            : base(dataPlane, compression, sink)
        {
            if (macAddress.Length != MacAddressLength) throw new ArgumentException("MAC address must be 6 bytes.", nameof(macAddress));
            if (mtu < 1) throw new ArgumentOutOfRangeException(nameof(mtu));
            _macAddress = macAddress;
            Mtu = mtu;
        }

        /// <inheritdoc/>
        public ReadOnlyMemory<byte> LinkAddress => _macAddress;

        /// <inheritdoc/>
        public LinkMedium Medium => LinkMedium.Ethernet;

        /// <inheritdoc/>
        public int Mtu { get; }

        /// <inheritdoc/>
        public int MaxHeaderLength => EthernetHeaderLength;

        /// <inheritdoc/>
        public bool RequiresLinkAddressResolution => true;

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? InboundFrame;

        /// <inheritdoc/>
        public ValueTask WriteFrameAsync(ReadOnlyMemory<byte> ethernetFrame, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SendPayloadAsync(ethernetFrame.Span);
        }

        /// <inheritdoc/>
        public override void Deliver(ReadOnlySpan<byte> wire)
        {
            if (TryReceivePayload(wire, out byte[] frame)) InboundFrame?.Invoke(frame);
        }
    }
}
