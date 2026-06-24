using TqkLibrary.VpnClient.ZeroTier.Identity;
using TqkLibrary.VpnClient.ZeroTier.Vl1;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Enums;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Models;
using Xunit;

namespace TqkLibrary.VpnClient.ZeroTier.Tests
{
    /// <summary>
    /// Golden interop KAT for the VL1 HELLO armor (cipher 0, C25519_POLY1305_NONE), captured live from two real
    /// zerotier-one 1.16.2 nodes (V.7.3 live lab). The bytes below are a genuine HELLO from node
    /// <c>0ef6d8cebd</c> to node <c>7494911ed3</c> on the wire. We derive the shared key from the two nodes' Curve25519
    /// keys and assert <see cref="Vl1PacketCodec.Open"/> dearmors it — i.e. our <c>_salsa20MangleKey</c> + Salsa20/12 +
    /// Poly1305 MAC matches zerotier-one byte-for-byte. The packet is public wire data (no secret committed beyond the
    /// nodes' own keys, which are throwaway lab identities), so hardcoding it locks interop permanently.
    /// </summary>
    public class Vl1HelloInteropKatTests
    {
        // Real HELLO packet 0ef6d8cebd -> 7494911ed3 (154 bytes), cipher 0, verb HELLO.
        const string HelloHex =
            "5ce806e137690b487494911ed30ef6d8cebd006c8bf42ef85961d3010d011000" +
            "020000019ef8a6a2ea0ef6d8cebd00490d7a076365facb4bb070cca733d25105" +
            "5fbd089a5dc372b67c07295b84a108dbb9c861d301d92bbdda8ecf89dbd4a204" +
            "b044946f8f1af5883106c4c66d60170004ac13000227090000000008eac90a00" +
            "000194db795b4e4042b6a4e3035f5cab7d7fa8702306281ed57a";

        // Throwaway lab node identities (idtool format addr:0:pub:priv). The Curve25519 halves are the first 32 bytes.
        const string SenderSecret =
            "0ef6d8cebd:0:490d7a076365facb4bb070cca733d251055fbd089a5dc372b67c07295b84a108dbb9c861d301d92bbdda8ecf89dbd4a204b044946f8f1af5883106c4c66d6017" +
            ":1cf9b219d9693b2eed3d24a43e0033a5a5fa52c830efcac164ad0c592f27bbfdae6c19ffd91a37c600adec412dd1b5c145ab519c288a6ca5d046469f78b909d3";
        const string ReceiverPublic =
            "7494911ed3:0:02df0fa2fca3ef4e618c063d325217d5484b4b3de85302c3731481098841525b08e3ff6b728ce7f4f73496489159680827d4f96bd2fcc048bff57d07fe320d28";

        static byte[] FromHex(string hex)
        {
            byte[] b = new byte[hex.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return b;
        }

        [Fact]
        public void Open_RealZeroTierHello_DearmorsWithSharedKey()
        {
            var idCodec = new ZeroTierIdentityCodec();
            var sender = idCodec.ParseString(SenderSecret);
            var receiver = idCodec.ParseString(ReceiverPublic);

            // The receiver would compute agree(receiverPriv, senderPub); we have senderPriv + receiverPub, which yields
            // the identical X25519 shared secret. Either direction derives the same key.
            byte[] key = new Vl1KeyDerivation().DeriveSharedKey(sender.Curve25519Private, receiver.Curve25519Public);

            byte[] packet = FromHex(HelloHex);
            bool ok = new Vl1PacketCodec().Open(packet, key, out var header, out byte[] payload);

            Assert.True(ok, "our codec must dearmor a real zerotier-one HELLO (MAC matches => mangle+Salsa20/12+Poly1305 correct)");
            Assert.Equal(Vl1CipherSuite.Poly1305None, header.Cipher);
            Assert.Equal(Vl1Verb.Hello, header.Verb);
            Assert.Equal("7494911ed3", header.Destination.ToString());
            Assert.Equal("0ef6d8cebd", header.Source.ToString());

            // The HELLO body decodes (it is plaintext for cipher 0): protocol version 13, identity embeds the sender.
            Assert.True(new HelloMessageCodec().TryDecode(payload, out var hello));
            Assert.Equal(13, hello.ProtocolVersion);
            Assert.Equal("0ef6d8cebd", hello.Identity.Address.ToString());
        }

        /// <summary>
        /// The send direction: re-seal the same HELLO body with the same header + shared key and assert the 8-byte MAC
        /// we produce equals the MAC zerotier-one put on the wire. A byte-exact MAC proves our <c>armor</c> output is
        /// what a real node accepts — the converse of the dearmor KAT above.
        /// </summary>
        [Fact]
        public void Seal_ReproducesRealZeroTierHelloMac()
        {
            var idCodec = new ZeroTierIdentityCodec();
            var sender = idCodec.ParseString(SenderSecret);
            var receiver = idCodec.ParseString(ReceiverPublic);
            byte[] key = new Vl1KeyDerivation().DeriveSharedKey(sender.Curve25519Private, receiver.Curve25519Public);

            byte[] real = FromHex(HelloHex);
            // The HELLO body is the plaintext after the verb byte (cipher 0 is not encrypted).
            byte[] body = real.AsSpan(Vl1Header.EncryptedSectionOffset + 1).ToArray();

            var header = new Vl1Header
            {
                PacketId = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(real.AsSpan(0, 8)),
                Destination = new Identity.Models.ZeroTierAddress(0x7494911ed3UL),
                Source = new Identity.Models.ZeroTierAddress(0x0ef6d8cebdUL),
                Cipher = Vl1CipherSuite.Poly1305None,
                Verb = Vl1Verb.Hello,
            };
            byte[] resealed = new Vl1PacketCodec().Seal(header, key, body);

            Assert.Equal(real.Length, resealed.Length);
            // Whole packet must be identical: same header, same plaintext body, same MAC.
            Assert.Equal(real, resealed);
        }
    }
}
