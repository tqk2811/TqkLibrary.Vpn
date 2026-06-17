using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;

namespace TqkLibrary.VpnClient.SoftEther.DataChannel
{
    /// <summary>
    /// The SoftEther data session as an L2 <see cref="IEthernetChannel"/>: it carries full Ethernet frames over the TLS
    /// byte stream ("Ethernet over HTTPS"), so it plugs straight into the userspace Ethernet fabric (ARP + DHCP + the
    /// <c>VirtualHost</c> bridge), which then bridges down to the IP stack — the stack never binds here directly. Because
    /// the payload is a complete Ethernet frame, <see cref="MaxHeaderLength"/> is 14 and
    /// <see cref="RequiresLinkAddressResolution"/> is true (the fabric resolves next-hop MACs via ARP).
    /// <para>
    /// Egress (<see cref="WriteFrameAsync"/>) seals the frame into a one-frame data block (<see cref="SoftEtherDataFrameCodec"/>)
    /// and hands it to the supplied <c>sink</c> (the connection's transport write). Ingress is push-driven: the connection's
    /// receive loop decodes inbound blocks and calls <see cref="Deliver"/> for each non-keep-alive frame, which raises
    /// <see cref="InboundFrame"/>. This type holds no socket itself, mirroring <c>OpenVpnTapChannel</c>.
    /// </para>
    /// </summary>
    public sealed class SoftEtherEthernetChannel : IEthernetChannel
    {
        const int EthernetHeaderLength = 14;
        const int MacAddressLength = 6;

        readonly ReadOnlyMemory<byte> _macAddress;
        readonly Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> _sink;

        /// <summary>
        /// Wires the channel. <paramref name="macAddress"/> is this endpoint's 6-byte MAC; <paramref name="sink"/> writes
        /// an encoded data block to the transport (an outbound send may also feed a keep-alive timer).
        /// </summary>
        public SoftEtherEthernetChannel(ReadOnlyMemory<byte> macAddress,
            Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> sink, int mtu = 1500)
        {
            if (macAddress.Length != MacAddressLength) throw new ArgumentException("MAC address must be 6 bytes.", nameof(macAddress));
            if (mtu < 1) throw new ArgumentOutOfRangeException(nameof(mtu));
            _macAddress = macAddress;
            _sink = sink ?? throw new ArgumentNullException(nameof(sink));
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
            byte[] block = SoftEtherDataFrameCodec.EncodeSingle(ethernetFrame);
            return _sink(block, cancellationToken);
        }

        /// <summary>
        /// Surfaces one inbound payload to the fabric. The connection's receive loop calls this for each frame it decoded
        /// from an inbound data block; a keep-alive payload is dropped (it is not an Ethernet frame).
        /// </summary>
        public void Deliver(ReadOnlyMemory<byte> frame)
        {
            if (SoftEtherDataFrameCodec.IsKeepAlive(frame.Span)) return;   // idle keep-alive — not a frame
            if (frame.Length < EthernetHeaderLength) return;              // too short to be an Ethernet frame
            InboundFrame?.Invoke(frame);
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            InboundFrame = null;
            return default;
        }
    }
}
