using System.Buffers.Binary;
using TqkLibrary.VpnClient.ZeroTier.Identity;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Models;

namespace TqkLibrary.VpnClient.ZeroTier.Vl1
{
    /// <summary>
    /// Encodes and decodes the body of a VL1 <c>HELLO</c> message (the bytes after the verb byte). The fixed prefix is
    /// 13 bytes — protocol version (1), major (1), minor (1), revision (2 BE), timestamp (8 BE) — followed by the
    /// sender's serialized identity in ZeroTier's <c>Identity::serialize</c> form
    /// (address(5) || type(1) || publicKey(64) || privateKeyLen(1)=0), then an optional physical-destination
    /// <c>InetAddress</c> (a single 0x00 byte = nil, which the receiver parses but does not require) and optional world
    /// IDs. The receiver (<c>_doHELLO</c>) treats every field after the identity as optional, so a HELLO ending right
    /// after the nil physical destination is accepted and answered with OK(HELLO).
    /// </summary>
    public sealed class HelloMessageCodec
    {
        const int FixedPrefix = 1 + 1 + 1 + 2 + 8;     // 13
        const int IdentitySerialized = 5 + 1 + 64 + 1; // address + type + publicKey + privateKeyLen(=0)

        readonly ZeroTierIdentityCodec _identityCodec = new ZeroTierIdentityCodec();

        /// <summary>
        /// Serialises the HELLO body (everything after the verb byte). When <paramref name="includePhysicalDestNil"/>
        /// is true a single 0x00 byte (a nil <c>InetAddress</c>) is appended after the identity, mirroring what a real
        /// node sends; the receiver's optional-field parser accepts it.
        /// </summary>
        public byte[] Encode(HelloMessage hello, bool includePhysicalDestNil = true)
        {
            if (hello is null) throw new ArgumentNullException(nameof(hello));
            // Full Identity::serialize form, including the trailing private-key-length byte (0 for a public identity).
            byte[] identity = _identityCodec.EncodeBinary(hello.Identity, includePrivate: false);
            int tail = includePhysicalDestNil ? 1 : 0;
            byte[] body = new byte[FixedPrefix + identity.Length + tail];

            int o = 0;
            body[o++] = hello.ProtocolVersion;
            body[o++] = hello.VersionMajor;
            body[o++] = hello.VersionMinor;
            BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(o, 2), hello.VersionRevision);
            o += 2;
            BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(o, 8), hello.Timestamp);
            o += 8;
            identity.CopyTo(body.AsSpan(o));
            o += identity.Length;
            if (includePhysicalDestNil) body[o] = 0x00; // nil InetAddress physical destination
            return body;
        }

        /// <summary>Parses a HELLO body. Returns false if too short or the embedded identity is malformed.</summary>
        public bool TryDecode(ReadOnlySpan<byte> body, out HelloMessage hello)
        {
            hello = new HelloMessage();
            if (body.Length < FixedPrefix + IdentitySerialized) return false;

            int o = 0;
            hello.ProtocolVersion = body[o++];
            hello.VersionMajor = body[o++];
            hello.VersionMinor = body[o++];
            hello.VersionRevision = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(o, 2));
            o += 2;
            hello.Timestamp = BinaryPrimitives.ReadUInt64BigEndian(body.Slice(o, 8));
            o += 8;

            if (!_identityCodec.TryDecodeBinary(body.Slice(o, IdentitySerialized), out var identity)) return false;
            hello.Identity = identity;
            return true;
        }
    }
}
