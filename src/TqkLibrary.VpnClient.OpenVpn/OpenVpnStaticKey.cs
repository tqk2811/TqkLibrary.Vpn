using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.OpenVpn.Enums;

namespace TqkLibrary.VpnClient.OpenVpn
{
    /// <summary>
    /// An OpenVPN 2048-bit static key (<c>ta.key</c>) — the shared secret behind <c>--tls-auth</c> and
    /// <c>--tls-crypt</c>. On disk/inline it is the <c>-----BEGIN OpenVPN Static key V1-----</c> block: 16 lines of
    /// 32 hex digits = 256 bytes. Those 256 bytes are the <c>key2</c> structure — two key sets, each
    /// <c>cipher[64] | hmac[64]</c>:
    /// <code>
    ///   set 0 cipher  [  0.. 64)   set 0 hmac  [ 64..128)
    ///   set 1 cipher  [128..192)   set 1 hmac  [192..256)
    /// </code>
    /// <see cref="OpenVpnTlsAuthWrap"/> uses the hmac halves; <see cref="OpenVpnTlsCryptWrap"/> uses both. The
    /// <see cref="OpenVpnKeyDirection"/> picks which set is out vs in so the two peers stay complementary.
    /// </summary>
    public sealed class OpenVpnStaticKey
    {
        /// <summary>The static key length in bytes (2048 bits).</summary>
        public const int KeyLength = 256;

        const int KeySetSize = 128; // cipher[64] | hmac[64]
        const int CipherOffset = 0;
        const int HmacOffset = 64;

        readonly byte[] _material;

        OpenVpnStaticKey(byte[] material) => _material = material;

        /// <summary>The raw 256-byte key material.</summary>
        public ReadOnlySpan<byte> Material => _material;

        /// <summary>
        /// Parses the <c>-----BEGIN OpenVPN Static key V1-----</c> block (or a bare 256-byte hex blob). Lines that are
        /// PEM-style markers (<c>-----…-----</c>), comments (<c>#</c>) or blank are ignored; the rest must be exactly
        /// 512 hex digits (256 bytes).
        /// </summary>
        public static OpenVpnStaticKey Parse(string text)
        {
            if (text is null) throw new ArgumentNullException(nameof(text));

            var hex = new System.Text.StringBuilder(512);
            foreach (string raw in text.Split('\n'))
            {
                string line = raw.Trim();
                if (line.Length == 0 || line[0] == '#' || line.StartsWith("-----")) continue;
                foreach (char c in line)
                    if (!char.IsWhiteSpace(c)) hex.Append(c);
            }

            byte[] material = HexCodec.Decode(hex.ToString());
            if (material.Length != KeyLength)
                throw new FormatException($"OpenVPN static key must be {KeyLength} bytes (got {material.Length}).");
            return new OpenVpnStaticKey(material);
        }

        /// <summary>Creates a key directly from 256 raw bytes (e.g. test material).</summary>
        public static OpenVpnStaticKey FromBytes(byte[] material)
        {
            if (material is null) throw new ArgumentNullException(nameof(material));
            if (material.Length != KeyLength)
                throw new ArgumentException($"OpenVPN static key must be {KeyLength} bytes.", nameof(material));
            return new OpenVpnStaticKey((byte[])material.Clone());
        }

        /// <summary>Resolves a key direction to the (outgoing set, incoming set) indices used by the two peers.</summary>
        public static (int OutKey, int InKey) ResolveDirection(OpenVpnKeyDirection direction) => direction switch
        {
            OpenVpnKeyDirection.Normal => (0, 1),
            OpenVpnKeyDirection.Inverse => (1, 0),
            _ => (0, 0),
        };

        /// <summary>The first <paramref name="length"/> bytes of key set <paramref name="setIndex"/>'s HMAC half.</summary>
        public byte[] HmacKey(int setIndex, int length) => Slice(setIndex * KeySetSize + HmacOffset, length);

        /// <summary>The first <paramref name="length"/> bytes of key set <paramref name="setIndex"/>'s cipher half.</summary>
        public byte[] CipherKey(int setIndex, int length) => Slice(setIndex * KeySetSize + CipherOffset, length);

        byte[] Slice(int offset, int length)
        {
            byte[] result = new byte[length];
            Array.Copy(_material, offset, result, 0, length);
            return result;
        }
    }
}
