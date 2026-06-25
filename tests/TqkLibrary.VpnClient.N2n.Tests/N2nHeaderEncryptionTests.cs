using TqkLibrary.VpnClient.N2n;
using Xunit;

namespace TqkLibrary.VpnClient.N2n.Tests
{
    /// <summary>
    /// n2n v3 header-encryption (<c>-H</c>) interop KATs. The golden packet was produced by the real n2n v3.1.1
    /// <c>packet_header_encrypt</c> (libn2n.a) over a fixed common-header packet for community <c>labnet</c> with a fixed
    /// timestamp, so decrypting it here must recover the original cleartext header and the timestamp byte-exact. Encrypt
    /// is randomised (the pre-IV embeds a random word), so the encrypt test asserts a round-trip rather than fixed bytes.
    /// </summary>
    public class N2nHeaderEncryptionTests
    {
        const string Community = "labnet";

        // packet_header_encrypt(packet, header_len=24, packet_len=48, stamp=0x0000017fabcdef12) over:
        //   plain48 = common header (v3 ttl2 flags0x0005 community "labnet") + 24 payload bytes 0x11..0x28
        const string PlainHex =
            "030200056c61626e657400000000000000000000000000001112131415161718191a1b1c1d1e1f202122232425262728";
        const string EncHex =
            "c82ddb3908f8abf55db3abcd10f0c30639b19a16f276f89b1112131415161718191a1b1c1d1e1f202122232425262728";
        const ulong Stamp = 0x0000017fabcdef12UL;
        // The random word n2n placed at pre-IV bytes 12..15 for the golden packet (recovered by decrypting its IV block).
        const string GoldenRandom4 = "c7dd61ee";

        static byte[] Hex(string h) => Convert.FromHexString(h);

        [Fact]
        public void Decrypt_RealN2nHeader_RecoversCleartextAndStamp()
        {
            var he = new N2nHeaderEncryption(Community);
            byte[] packet = Hex(EncHex);

            Assert.True(he.Decrypt(packet, packet.Length, out ulong stamp));
            Assert.Equal(Stamp, stamp);
            Assert.Equal(Hex(PlainHex), packet);   // header restored, payload untouched
        }

        [Fact]
        public void Decrypt_WrongCommunity_Rejected()
        {
            var he = new N2nHeaderEncryption("notlabnet");
            byte[] packet = Hex(EncHex);
            Assert.False(he.Decrypt(packet, packet.Length, out _));
        }

        [Fact]
        public void EncryptThenDecrypt_RoundTrips()
        {
            var he = new N2nHeaderEncryption(Community);
            byte[] plain = Hex(PlainHex);
            byte[] packet = (byte[])plain.Clone();
            byte[] random16 = Convert.FromHexString("00112233445566778899aabbccddeeff");

            Assert.True(he.Encrypt(packet, 24, packet.Length, Stamp, random16));
            Assert.NotEqual(plain, packet);                 // header is now ciphertext
            Assert.Equal(plain.AsSpan(24).ToArray(), packet.AsSpan(24).ToArray()); // payload untouched

            Assert.True(he.Decrypt(packet, packet.Length, out ulong stamp));
            Assert.Equal(Stamp, stamp);
            Assert.Equal(plain, packet);
        }

        [Fact]
        public void Decrypt_TamperedHeader_FailsChecksum()
        {
            var he = new N2nHeaderEncryption(Community);
            byte[] packet = Hex(EncHex);
            packet[22] ^= 0x01; // flip a bit inside the encrypted IV block -> checksum mismatch
            Assert.False(he.Decrypt(packet, packet.Length, out _));
        }

        [Fact]
        public void Encrypt_WithGoldenRandom_ReproducesRealN2nBytes()
        {
            // Feeding the same random word n2n used reproduces the golden ciphertext byte-exact: proof the encrypt path
            // (not just decrypt) matches n2n's packet_header_encrypt end-to-end.
            var he = new N2nHeaderEncryption(Community);
            byte[] packet = Hex(PlainHex);
            Assert.True(he.Encrypt(packet, 24, packet.Length, Stamp, Hex(GoldenRandom4)));
            Assert.Equal(Hex(EncHex), packet);
        }
    }
}
