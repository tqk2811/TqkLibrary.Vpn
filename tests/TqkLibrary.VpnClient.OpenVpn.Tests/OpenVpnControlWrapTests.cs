using System.Security.Cryptography;
using TqkLibrary.VpnClient.OpenVpn;
using TqkLibrary.VpnClient.OpenVpn.Enums;
using TqkLibrary.VpnClient.OpenVpn.Models;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>
    /// Codec-level tests for the control-channel wrap layer (V2.c): <see cref="OpenVpnTlsAuthWrap"/> (HMAC) and
    /// <see cref="OpenVpnTlsCryptWrap"/> (HMAC + AES-256-CTR). They verify round-trip between the two complementary
    /// directions, tamper detection, wrong-key rejection, that tls-crypt actually encrypts the body, and that the
    /// static-key parser reads the 2048-bit <c>ta.key</c> block.
    /// </summary>
    public class OpenVpnControlWrapTests
    {
        static OpenVpnStaticKey TestKey()
        {
            byte[] material = new byte[OpenVpnStaticKey.KeyLength];
            for (int i = 0; i < material.Length; i++) material[i] = (byte)(i * 7 + 3);
            return OpenVpnStaticKey.FromBytes(material);
        }

        static byte[] SampleControlPacket() => OpenVpnPacketCodec.EncodeControl(new OpenVpnControlPacket
        {
            Opcode = OpenVpnOpcode.ControlV1,
            KeyId = 0,
            SessionId = 0xA1B2C3D4E5F60718UL,
            AckPacketIds = new uint[] { 1, 2 },
            RemoteSessionId = 0x1122334455667788UL,
            PacketId = 5,
            Payload = new byte[] { 0x16, 0x03, 0x03, 0xDE, 0xAD, 0xBE, 0xEF },
        });

        [Fact]
        public void TlsAuth_RoundTrips_BetweenComplementaryDirections()
        {
            var key = TestKey();
            var client = new OpenVpnTlsAuthWrap(key, OpenVpnKeyDirection.Inverse, HashAlgorithmName.SHA256, () => 1000u);
            var server = new OpenVpnTlsAuthWrap(key, OpenVpnKeyDirection.Normal, HashAlgorithmName.SHA256, () => 2000u);

            byte[] packet = SampleControlPacket();

            byte[] wire = client.Wrap(packet);
            Assert.True(server.TryUnwrap(wire, out byte[] atServer));
            Assert.Equal(packet, atServer);

            byte[] back = server.Wrap(atServer);
            Assert.True(client.TryUnwrap(back, out byte[] atClient));
            Assert.Equal(packet, atClient);
        }

        [Fact]
        public void TlsAuth_DefaultsToSha1_AndCarries20ByteTag()
        {
            var key = TestKey();
            var client = new OpenVpnTlsAuthWrap(key, OpenVpnKeyDirection.Inverse);
            var server = new OpenVpnTlsAuthWrap(key, OpenVpnKeyDirection.Normal);

            byte[] packet = SampleControlPacket();
            byte[] wire = client.Wrap(packet);

            // op(1)+session_id(8) + HMAC-SHA1(20) + replay_id(4)+net_time(4) + body
            Assert.Equal(packet.Length + 20 + 8, wire.Length);
            Assert.True(server.TryUnwrap(wire, out byte[] plain));
            Assert.Equal(packet, plain);
        }

        [Fact]
        public void TlsAuth_RejectsTamperedTagOrBody()
        {
            var key = TestKey();
            var client = new OpenVpnTlsAuthWrap(key, OpenVpnKeyDirection.Inverse, HashAlgorithmName.SHA256, () => 1u);
            var server = new OpenVpnTlsAuthWrap(key, OpenVpnKeyDirection.Normal, HashAlgorithmName.SHA256, () => 1u);

            byte[] wire = client.Wrap(SampleControlPacket());
            wire[^1] ^= 0xFF; // flip a body byte
            Assert.False(server.TryUnwrap(wire, out _));
        }

        [Fact]
        public void TlsAuth_RejectsWrongKey()
        {
            var client = new OpenVpnTlsAuthWrap(TestKey(), OpenVpnKeyDirection.Inverse, HashAlgorithmName.SHA256, () => 1u);

            byte[] other = new byte[OpenVpnStaticKey.KeyLength];
            for (int i = 0; i < other.Length; i++) other[i] = (byte)(i * 11 + 1);
            var server = new OpenVpnTlsAuthWrap(OpenVpnStaticKey.FromBytes(other), OpenVpnKeyDirection.Normal, HashAlgorithmName.SHA256, () => 1u);

            byte[] wire = client.Wrap(SampleControlPacket());
            Assert.False(server.TryUnwrap(wire, out _));
        }

        [Fact]
        public void TlsCrypt_RoundTrips_AndEncryptsBody()
        {
            var key = TestKey();
            var client = new OpenVpnTlsCryptWrap(key, isServer: false, () => 1000u);
            var server = new OpenVpnTlsCryptWrap(key, isServer: true, () => 2000u);

            byte[] packet = SampleControlPacket();
            byte[] wire = client.Wrap(packet);

            // op(1)+session_id(8) + packet_id(8) + tag(32) + ciphertext(body length)
            int bodyLen = packet.Length - 9;
            Assert.Equal(9 + 8 + 32 + bodyLen, wire.Length);

            // The header (op|session_id) is in the clear; the body is encrypted (differs from plaintext body).
            Assert.True(packet.AsSpan(0, 9).SequenceEqual(wire.AsSpan(0, 9)));
            Assert.False(packet.AsSpan(9, bodyLen).SequenceEqual(wire.AsSpan(9 + 8 + 32, bodyLen)));

            Assert.True(server.TryUnwrap(wire, out byte[] atServer));
            Assert.Equal(packet, atServer);

            byte[] back = server.Wrap(atServer);
            Assert.True(client.TryUnwrap(back, out byte[] atClient));
            Assert.Equal(packet, atClient);
        }

        [Fact]
        public void TlsCrypt_RejectsTamperedCiphertext()
        {
            var key = TestKey();
            var client = new OpenVpnTlsCryptWrap(key, isServer: false, () => 1u);
            var server = new OpenVpnTlsCryptWrap(key, isServer: true, () => 1u);

            byte[] wire = client.Wrap(SampleControlPacket());
            wire[^1] ^= 0x01;
            Assert.False(server.TryUnwrap(wire, out _));
        }

        [Fact]
        public void StaticKey_ParsesOpenVpnKeyBlock()
        {
            byte[] material = new byte[OpenVpnStaticKey.KeyLength];
            for (int i = 0; i < material.Length; i++) material[i] = (byte)i;

            // Render the bytes as the canonical 16-line hex block, then parse it back.
            var sb = new System.Text.StringBuilder();
            sb.Append("-----BEGIN OpenVPN Static key V1-----\n");
            sb.Append("#\n# 2048 bit OpenVPN static key\n#\n");
            for (int line = 0; line < 16; line++)
            {
                for (int b = 0; b < 16; b++) sb.Append(material[line * 16 + b].ToString("x2"));
                sb.Append('\n');
            }
            sb.Append("-----END OpenVPN Static key V1-----\n");

            var key = OpenVpnStaticKey.Parse(sb.ToString());
            Assert.True(key.Material.SequenceEqual(material));

            // Key set 0 cipher = bytes [0..32), set 1 hmac = bytes [192..224).
            Assert.Equal(material.AsSpan(0, 32).ToArray(), key.CipherKey(0, 32));
            Assert.Equal(material.AsSpan(192, 32).ToArray(), key.HmacKey(1, 32));
        }

        [Fact]
        public void StaticKey_RejectsWrongLength()
        {
            Assert.Throws<FormatException>(() => OpenVpnStaticKey.Parse("00112233"));
        }
    }
}
