using System.Buffers.Binary;
using TqkLibrary.VpnClient.ZeroTier.Vl2.Models;

namespace TqkLibrary.VpnClient.ZeroTier.Vl2
{
    /// <summary>
    /// Encodes and decodes the body of a VL1 <c>EXT_FRAME</c> verb — a VL2 Ethernet frame with explicit MACs and an
    /// optional attached certificate of membership. Body layout:
    /// <c>networkId(8) || flags(1) || [com] || destMac(6) || srcMac(6) || etherType(2) || frameData</c>, where the COM is
    /// present iff <c>flags &amp; 0x01</c>. The COM is self-describing
    /// (<c>version(1) || qualifierCount(2 BE) || qualifiers(24×count) || signedBy(5) || signature(64)</c>), so its length
    /// is computed from the qualifier count without re-signing or parsing the qualifiers.
    /// </summary>
    public sealed class Vl2ExtFrameCodec
    {
        const int MacLength = 6;
        const int ComFixedOverhead = 1 + 2 + 5 + 64; // version + qualifierCount + signedBy + signature
        const int ComQualifierSize = 24;             // id(8) + value(8) + maxDelta(8)
        const int FixedAfterCom = MacLength + MacLength + 2; // dstMac + srcMac + etherType

        /// <summary>Serialises an EXT_FRAME body. When <paramref name="frame"/> has a COM and the COM-attached flag, the
        /// COM blob is written immediately after the flags byte.</summary>
        public byte[] Encode(Vl2ExtFrame frame)
        {
            if (frame is null) throw new System.ArgumentNullException(nameof(frame));
            bool comAttached = (frame.Flags & Vl2ExtFrame.FlagComAttached) != 0 && frame.CertificateOfMembership is { Length: > 0 };
            byte[] com = comAttached ? frame.CertificateOfMembership! : System.Array.Empty<byte>();

            int len = NetworkId.SizeInBytes + 1 + com.Length + FixedAfterCom + frame.FrameData.Length;
            byte[] body = new byte[len];
            int o = 0;
            frame.Network.Write(body.AsSpan(o, NetworkId.SizeInBytes));
            o += NetworkId.SizeInBytes;
            body[o++] = comAttached ? (byte)(frame.Flags | Vl2ExtFrame.FlagComAttached) : (byte)(frame.Flags & ~Vl2ExtFrame.FlagComAttached);
            if (comAttached) { com.CopyTo(body, o); o += com.Length; }
            frame.DestinationMac.AsSpan(0, MacLength).CopyTo(body.AsSpan(o)); o += MacLength;
            frame.SourceMac.AsSpan(0, MacLength).CopyTo(body.AsSpan(o)); o += MacLength;
            BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(o, 2), frame.EtherType); o += 2;
            frame.FrameData.CopyTo(body.AsSpan(o));
            return body;
        }

        /// <summary>Parses an EXT_FRAME body. Returns false on a truncated buffer.</summary>
        public bool TryDecode(ReadOnlySpan<byte> body, out Vl2ExtFrame frame)
        {
            frame = new Vl2ExtFrame();
            if (body.Length < NetworkId.SizeInBytes + 1) return false;

            int o = 0;
            frame.Network = NetworkId.Read(body.Slice(o, NetworkId.SizeInBytes));
            o += NetworkId.SizeInBytes;
            frame.Flags = body[o++];

            if ((frame.Flags & Vl2ExtFrame.FlagComAttached) != 0)
            {
                if (body.Length - o < 1 + 2) return false;
                int qualifierCount = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(o + 1, 2));
                int comLen = ComFixedOverhead + qualifierCount * ComQualifierSize;
                if (body.Length - o < comLen) return false;
                frame.CertificateOfMembership = body.Slice(o, comLen).ToArray();
                o += comLen;
            }

            if (body.Length - o < FixedAfterCom) return false;
            frame.DestinationMac = body.Slice(o, MacLength).ToArray(); o += MacLength;
            frame.SourceMac = body.Slice(o, MacLength).ToArray(); o += MacLength;
            frame.EtherType = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(o, 2)); o += 2;
            frame.FrameData = body.Slice(o).ToArray();
            return true;
        }
    }
}
