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
        readonly bool _useCompress;

        /// <summary>
        /// Wires the channel. <paramref name="macAddress"/> is this endpoint's 6-byte MAC; <paramref name="sink"/> writes
        /// an encoded data block to the transport (an outbound send may also feed a keep-alive timer). When
        /// <paramref name="useCompress"/> is <c>true</c> (the negotiated <c>use_compress</c> session flag) each outbound
        /// frame is DEFLATE-compressed (<see cref="SoftEtherPayloadCompressor"/>) before it is block-encoded and each
        /// inbound frame is decompressed in <see cref="Deliver"/>; the default keeps the payload raw on TLS.
        /// </summary>
        public SoftEtherEthernetChannel(ReadOnlyMemory<byte> macAddress,
            Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> sink, int mtu = 1500, bool useCompress = false)
        {
            if (macAddress.Length != MacAddressLength) throw new ArgumentException("MAC address must be 6 bytes.", nameof(macAddress));
            if (mtu < 1) throw new ArgumentOutOfRangeException(nameof(mtu));
            _macAddress = macAddress;
            _sink = sink ?? throw new ArgumentNullException(nameof(sink));
            _useCompress = useCompress;
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
            // use_compress: DEFLATE the frame before it is sealed into a block (the receiver decompresses in Deliver).
            ReadOnlyMemory<byte> payload = _useCompress
                ? SoftEtherPayloadCompressor.CompressFrame(ethernetFrame.Span)
                : ethernetFrame;
            byte[] block = SoftEtherDataFrameCodec.EncodeSingle(payload);
            return _sink(block, cancellationToken);
        }

        /// <summary>
        /// Surfaces one inbound payload to the fabric. The connection's receive loop calls this for each frame it decoded
        /// from an inbound data block; a keep-alive payload is dropped (it is not an Ethernet frame). When
        /// <c>use_compress</c> is on the frame is decompressed first (a compressed frame is recognised by its magic
        /// prefix, so a raw keep-alive still passes through unchanged).
        /// </summary>
        public void Deliver(ReadOnlyMemory<byte> frame)
        {
            ReadOnlyMemory<byte> payload = _useCompress
                ? SoftEtherPayloadCompressor.DecompressFrame(frame.Span)
                : frame;
            if (SoftEtherDataFrameCodec.IsKeepAlive(payload.Span)) return;   // idle keep-alive — not a frame
            if (payload.Length < EthernetHeaderLength) return;              // too short to be an Ethernet frame
            InboundFrame?.Invoke(payload);
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            InboundFrame = null;
            return default;
        }
    }
}
