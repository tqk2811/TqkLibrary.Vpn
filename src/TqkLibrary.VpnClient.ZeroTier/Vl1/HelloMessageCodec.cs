using System.Buffers.Binary;
using TqkLibrary.VpnClient.ZeroTier.Identity;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Models;

namespace TqkLibrary.VpnClient.ZeroTier.Vl1
{
    /// <summary>
    /// Encodes and decodes the body of a VL1 <c>HELLO</c> message (the bytes after the verb byte). The fixed prefix is
    /// 13 bytes — protocol version (1), major (1), minor (1), revision (2 BE), timestamp (8 BE) — followed by the
    /// sender's serialized identity (address(5) || type(1) || publicKey(64)). Trailing fields present in newer ZeroTier
    /// HELLOs (physical destination, world IDs, encrypted dictionary) are not parsed here.
    /// </summary>
    public sealed class HelloMessageCodec
    {
        const int FixedPrefix = 1 + 1 + 1 + 2 + 8; // 13
        const int IdentityFixed = 5 + 1 + 64;      // address + type + publicKey

        readonly ZeroTierIdentityCodec _identityCodec = new ZeroTierIdentityCodec();

        /// <summary>Serialises the HELLO body (everything after the verb byte).</summary>
        public byte[] Encode(HelloMessage hello)
        {
            if (hello is null) throw new ArgumentNullException(nameof(hello));
            byte[] identity = _identityCodec.EncodeBinary(hello.Identity, includePrivate: false);
            // EncodeBinary appends a private-key-length byte (0 here); drop it for the HELLO embedding.
            int idLen = IdentityFixed;
            byte[] body = new byte[FixedPrefix + idLen];

            int o = 0;
            body[o++] = hello.ProtocolVersion;
            body[o++] = hello.VersionMajor;
            body[o++] = hello.VersionMinor;
            BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(o, 2), hello.VersionRevision);
            o += 2;
            BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(o, 8), hello.Timestamp);
            o += 8;
            identity.AsSpan(0, idLen).CopyTo(body.AsSpan(o));
            return body;
        }

        /// <summary>Parses a HELLO body. Returns false if too short or the embedded identity is malformed.</summary>
        public bool TryDecode(ReadOnlySpan<byte> body, out HelloMessage hello)
        {
            hello = new HelloMessage();
            if (body.Length < FixedPrefix + IdentityFixed) return false;

            int o = 0;
            hello.ProtocolVersion = body[o++];
            hello.VersionMajor = body[o++];
            hello.VersionMinor = body[o++];
            hello.VersionRevision = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(o, 2));
            o += 2;
            hello.Timestamp = BinaryPrimitives.ReadUInt64BigEndian(body.Slice(o, 8));
            o += 8;

            // The embedded identity has no private-key-length suffix; decode the fixed part only.
            if (!_identityCodec.TryDecodeBinary(body.Slice(o, IdentityFixed), out var identity)) return false;
            hello.Identity = identity;
            return true;
        }
    }
}
