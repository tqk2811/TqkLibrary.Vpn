using TqkLibrary.VpnClient.Abstractions.Channels.Enums;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.ZeroTier.Identity.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl1;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Enums;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl2;
using TqkLibrary.VpnClient.ZeroTier.Vl2.Models;

namespace TqkLibrary.VpnClient.Drivers.ZeroTier.DataChannel
{
    /// <summary>
    /// The ZeroTier data session as an L2 <see cref="IEthernetChannel"/>: it carries full Ethernet frames as VL2
    /// <c>EXT_FRAME</c> messages sealed inside encrypted VL1 packets, so it plugs straight into the userspace Ethernet
    /// fabric (ARP + the <c>VirtualHost</c> bridge), which then bridges down to the IP stack — the stack never binds
    /// here directly. Because the payload is a complete Ethernet frame, <see cref="MaxHeaderLength"/> is 14 and
    /// <see cref="RequiresLinkAddressResolution"/> is true (the fabric resolves next-hop MACs via ARP).
    /// <para>
    /// Egress (<see cref="WriteFrameAsync"/>) reads the destination/source MAC from the Ethernet header, wraps the frame
    /// in an EXT_FRAME (attaching the certificate of membership on the first send so the peer accepts us), and seals it as
    /// a Salsa20/12 + Poly1305 VL1 packet addressed to the peer node; the sealed datagram goes to the supplied
    /// <c>sink</c> (the connection's transport write). Ingress is push-driven: the connection's receive loop hands each
    /// decoded inbound EXT_FRAME/FRAME body to <see cref="Deliver"/>, which rebuilds the Ethernet frame and raises
    /// <see cref="InboundFrame"/>. This type holds no socket itself, mirroring <c>N2nEthernetChannel</c> /
    /// <c>SoftEtherEthernetChannel</c>.
    /// </para>
    /// </summary>
    public sealed class ZeroTierEthernetChannel : IEthernetChannel
    {
        const int EthernetHeaderLength = 14;
        const int MacAddressLength = 6;

        readonly Vl1PacketCodec _packetCodec;
        readonly Vl2ExtFrameCodec _extFrameCodec = new Vl2ExtFrameCodec();
        readonly Vl2FrameCodec _frameCodec = new Vl2FrameCodec();
        readonly byte[] _sessionKey;
        readonly NetworkId _network;
        readonly ZeroTierAddress _localAddress;
        readonly ZeroTierAddress _peerAddress;
        readonly byte[] _localMac;
        readonly byte[]? _certificateOfMembership;
        readonly Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> _sink;
        readonly Func<ulong> _nextPacketId;

        int _comSent; // attach the COM only until the peer has seen it once (0 = not yet sent)

        /// <summary>
        /// Wires the channel. <paramref name="sessionKey"/> is the 64-byte VL1 shared key (its first 32 bytes seed
        /// Salsa20); <paramref name="network"/> stamps every frame; <paramref name="localAddress"/>/
        /// <paramref name="peerAddress"/> are the VL1 src/dst node addresses; <paramref name="localMac"/> is this node's
        /// per-network MAC; <paramref name="certificateOfMembership"/> (may be null) is attached on the first frame to
        /// prove membership; <paramref name="sink"/> writes the sealed datagram; <paramref name="nextPacketId"/> supplies
        /// a fresh VL1 packet ID; <paramref name="mtu"/> is the tunnel MTU.
        /// </summary>
        public ZeroTierEthernetChannel(Vl1PacketCodec packetCodec, byte[] sessionKey, NetworkId network,
            ZeroTierAddress localAddress, ZeroTierAddress peerAddress, ReadOnlyMemory<byte> localMac,
            byte[]? certificateOfMembership, Func<ReadOnlyMemory<byte>, CancellationToken, ValueTask> sink,
            Func<ulong> nextPacketId, int mtu = ZeroTierDriverConstants.DefaultMtu)
        {
            if (localMac.Length != MacAddressLength) throw new ArgumentException("MAC address must be 6 bytes.", nameof(localMac));
            if (sessionKey is null || sessionKey.Length < 32) throw new ArgumentException("session key must be >= 32 bytes.", nameof(sessionKey));
            if (mtu < 1) throw new ArgumentOutOfRangeException(nameof(mtu));
            _packetCodec = packetCodec ?? throw new ArgumentNullException(nameof(packetCodec));
            _sessionKey = sessionKey;
            _network = network;
            _localAddress = localAddress;
            _peerAddress = peerAddress;
            _localMac = localMac.ToArray();
            _certificateOfMembership = certificateOfMembership;
            _sink = sink ?? throw new ArgumentNullException(nameof(sink));
            _nextPacketId = nextPacketId ?? throw new ArgumentNullException(nameof(nextPacketId));
            Mtu = mtu;
        }

        /// <inheritdoc/>
        public ReadOnlyMemory<byte> LinkAddress => _localMac;

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

            ReadOnlySpan<byte> span = ethernetFrame.Span;
            byte[] dstMac = span.Slice(0, MacAddressLength).ToArray();
            byte[] srcMac = span.Slice(MacAddressLength, MacAddressLength).ToArray();
            ushort etherType = (ushort)((span[12] << 8) | span[13]);
            byte[] payload = span.Slice(EthernetHeaderLength).ToArray();

            // Attach the certificate of membership so the peer accepts our frames. ZeroTier expects the COM presented to
            // each peer that asks (ERROR NEED_MEMBERSHIP_CERTIFICATE); attaching it on every EXT_FRAME until the peer has
            // it is the simplest interoperable behaviour (the COM is small relative to a data frame).
            bool attachCom = _certificateOfMembership is { Length: > 0 } && System.Threading.Volatile.Read(ref _comSent) == 0;

            var ext = new Vl2ExtFrame
            {
                Network = _network,
                Flags = attachCom ? Vl2ExtFrame.FlagComAttached : (byte)0,
                CertificateOfMembership = attachCom ? _certificateOfMembership : null,
                DestinationMac = dstMac,
                SourceMac = srcMac,
                EtherType = etherType,
                FrameData = payload,
            };
            byte[] body = _extFrameCodec.Encode(ext);
            byte[] datagram = SealVl1(Vl1Verb.ExtFrame, body);
            return _sink(datagram, cancellationToken);
        }

        /// <summary>
        /// Surfaces one inbound VL2 frame body to the fabric. The connection's receive loop calls this for each decoded
        /// EXT_FRAME (with the explicit MACs) or plain FRAME (MACs derived). The body is the payload after the VL1 verb
        /// byte. The recovered Ethernet frame is raised on <see cref="InboundFrame"/>.
        /// </summary>
        public void DeliverExtFrame(ReadOnlySpan<byte> extFrameBody)
        {
            if (!_extFrameCodec.TryDecode(extFrameBody, out Vl2ExtFrame ext)) return;
            byte[] frame = BuildEthernetFrame(ext.DestinationMac, ext.SourceMac, ext.EtherType, ext.FrameData);
            InboundFrame?.Invoke(frame);
        }

        /// <summary>
        /// Surfaces one inbound plain FRAME (no explicit MACs). The destination is this node, the source is the peer; both
        /// MACs are derived from the ZeroTier node addresses + network id, so the fabric sees a normal Ethernet frame.
        /// </summary>
        public void DeliverFrame(ReadOnlySpan<byte> frameBody)
        {
            if (!_frameCodec.TryDecode(frameBody, out Vl2Frame frame)) return;
            byte[] dstMac = _frameCodec.DeriveMac(_localAddress, _network);
            byte[] srcMac = _frameCodec.DeriveMac(_peerAddress, _network);
            byte[] eth = BuildEthernetFrame(dstMac, srcMac, frame.EtherType, frame.FrameData);
            InboundFrame?.Invoke(eth);
        }

        byte[] SealVl1(Vl1Verb verb, byte[] body)
        {
            var header = new Vl1Header
            {
                PacketId = _nextPacketId(),
                Destination = _peerAddress,
                Source = _localAddress,
                Cipher = Vl1CipherSuite.Salsa2012Poly1305, // data is encrypted
                Verb = verb,
            };
            return _packetCodec.Seal(header, _sessionKey, body);
        }

        static byte[] BuildEthernetFrame(byte[] dstMac, byte[] srcMac, ushort etherType, byte[] payload)
        {
            byte[] frame = new byte[EthernetHeaderLength + payload.Length];
            Array.Copy(dstMac, 0, frame, 0, MacAddressLength);
            Array.Copy(srcMac, 0, frame, MacAddressLength, MacAddressLength);
            frame[12] = (byte)(etherType >> 8);
            frame[13] = (byte)etherType;
            payload.CopyTo(frame, EthernetHeaderLength);
            return frame;
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            InboundFrame = null;
            return default;
        }
    }
}
