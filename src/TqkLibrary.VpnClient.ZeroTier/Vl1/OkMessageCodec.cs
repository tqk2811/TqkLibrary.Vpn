using System.Buffers.Binary;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Models;

namespace TqkLibrary.VpnClient.ZeroTier.Vl1
{
    /// <summary>
    /// Parses the body of a VL1 <c>OK</c> verb (the bytes after the verb byte, already decrypted — an OK is sealed with
    /// the encrypting Salsa20/12 + Poly1305 suite). Every OK shares a 9-byte common header
    /// <c>inReVerb(1) || inRePacketId(8 BE)</c>; this codec exposes that plus the <c>OK(HELLO)</c> verb-specific tail.
    /// </summary>
    public sealed class OkMessageCodec
    {
        /// <summary>Common-header length (in-re-verb + in-re-packet-id).</summary>
        public const int CommonHeaderLength = 1 + 8;

        readonly InetAddressCodec _inetCodec = new InetAddressCodec();

        /// <summary>Reads the common <c>inReVerb || inRePacketId</c> header. Returns false if the body is too short.</summary>
        public bool TryDecodeCommon(ReadOnlySpan<byte> body, out byte inReVerb, out ulong inRePacketId)
        {
            inReVerb = 0;
            inRePacketId = 0;
            if (body.Length < CommonHeaderLength) return false;
            inReVerb = body[0];
            inRePacketId = BinaryPrimitives.ReadUInt64BigEndian(body.Slice(1, 8));
            return true;
        }

        /// <summary>
        /// Parses an <c>OK(HELLO)</c> body. Returns false if the body is too short for the fixed fields; a missing or
        /// truncated physical-destination tail leaves <see cref="OkHelloMessage.PhysicalDestination"/> nil (the field is
        /// optional in practice).
        /// </summary>
        public bool TryDecodeOkHello(ReadOnlySpan<byte> body, out OkHelloMessage message)
        {
            message = new OkHelloMessage();
            // common(9) + timestamp(8) + protoVer(1) + major(1) + minor(1) + revision(2)
            const int fixedLen = CommonHeaderLength + 8 + 1 + 1 + 1 + 2;
            if (body.Length < fixedLen) return false;

            int o = 0;
            message.InReVerb = body[o++];
            message.InRePacketId = BinaryPrimitives.ReadUInt64BigEndian(body.Slice(o, 8));
            o += 8;
            message.TimestampEcho = BinaryPrimitives.ReadUInt64BigEndian(body.Slice(o, 8));
            o += 8;
            message.ProtocolVersion = body[o++];
            message.VersionMajor = body[o++];
            message.VersionMinor = body[o++];
            message.VersionRevision = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(o, 2));
            o += 2;

            if (o < body.Length && _inetCodec.TryDecode(body.Slice(o), out var physical, out _))
                message.PhysicalDestination = physical;
            return true;
        }
    }
}
