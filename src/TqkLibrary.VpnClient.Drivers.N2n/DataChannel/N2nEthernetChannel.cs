using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.N2n;
using TqkLibrary.VpnClient.N2n.Transform.Interfaces;
using TqkLibrary.VpnClient.N2n.Wire.Models;

namespace TqkLibrary.VpnClient.Drivers.N2n.DataChannel
{
    /// <summary>
    /// The n2n data session as an L2 <see cref="IEthernetChannel"/>: it carries full Ethernet frames as PACKET messages
    /// over the UDP transport, so it plugs straight into the userspace Ethernet fabric (ARP + the <c>VirtualHost</c>
    /// bridge), which then bridges down to the IP stack — the stack never binds here directly. Because the payload is a
    /// complete Ethernet frame, <see cref="MaxHeaderLength"/> is 14 and <see cref="RequiresLinkAddressResolution"/> is
    /// true (the fabric resolves next-hop MACs via ARP).
    /// <para>
    /// Egress (<see cref="WriteFrameAsync"/>) reads the destination MAC straight from the Ethernet header, encodes the
    /// frame into a PACKET (the configured <see cref="IN2nTransform"/> protects the payload), and hands the datagram to
    /// the supplied <c>sink</c> (the connection's transport write — relayed via the supernode). Ingress is push-driven:
    /// the connection's receive loop decodes inbound PACKETs and calls <see cref="Deliver"/> with the recovered Ethernet
    /// frame, which raises <see cref="InboundFrame"/>. This type holds no socket itself, mirroring
    /// <c>SoftEtherEthernetChannel</c> / <c>OpenVpnTapChannel</c>.
    /// </para>
    /// </summary>
    public sealed class N2nEthernetChannel : IEthernetChannel
    {
        const int EthernetHeaderLength = 14;
        const int MacAddressLength = 6;

        readonly N2nPacketCodec _codec;
        readonly string _community;
        readonly byte[] _srcMac;
        readonly IN2nTransform _transform;
        readonly Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> _sink;

        /// <summary>
        /// Wires the channel. <paramref name="community"/> + <paramref name="srcMac"/> stamp every outbound PACKET (this
        /// edge's identity); <paramref name="transform"/> protects the payload; <paramref name="sink"/> writes the
        /// encoded datagram to the transport. <paramref name="mtu"/> is the tunnel MTU.
        /// </summary>
        public N2nEthernetChannel(N2nPacketCodec codec, string community, ReadOnlyMemory<byte> srcMac,
            IN2nTransform transform, Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> sink, int mtu = 1290)
        {
            if (srcMac.Length != MacAddressLength) throw new ArgumentException("MAC address must be 6 bytes.", nameof(srcMac));
            if (mtu < 1) throw new ArgumentOutOfRangeException(nameof(mtu));
            _codec = codec ?? throw new ArgumentNullException(nameof(codec));
            _community = community ?? throw new ArgumentNullException(nameof(community));
            _srcMac = srcMac.ToArray();
            _transform = transform ?? throw new ArgumentNullException(nameof(transform));
            _sink = sink ?? throw new ArgumentNullException(nameof(sink));
            Mtu = mtu;
        }

        /// <inheritdoc/>
        public ReadOnlyMemory<byte> LinkAddress => _srcMac;

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
            if (ethernetFrame.Length < EthernetHeaderLength) return default; // too short to be an Ethernet frame

            // The Ethernet header's destination MAC (bytes 0..6) is the PACKET's dstMac; the supernode relays by it.
            byte[] dstMac = ethernetFrame.Slice(0, MacAddressLength).ToArray();
            var body = new N2nPacket
            {
                SrcMac = _srcMac,
                DstMac = dstMac,
                Transform = _transform.Id,
                Payload = ethernetFrame.ToArray(),
            };
            byte[] datagram = _codec.EncodePacket(_community, body, _transform);
            return _sink(datagram, cancellationToken);
        }

        /// <summary>
        /// Surfaces one inbound Ethernet frame to the fabric. The connection's receive loop calls this for each PACKET it
        /// decoded (the payload already run back through the transform). A frame too short to be an Ethernet frame is
        /// dropped.
        /// </summary>
        public void Deliver(ReadOnlyMemory<byte> ethernetFrame)
        {
            if (ethernetFrame.Length < EthernetHeaderLength) return;
            InboundFrame?.Invoke(ethernetFrame);
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            InboundFrame = null;
            return default;
        }
    }
}
