using TqkLibrary.VpnClient.ZeroTier.Identity.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl1;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Enums;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Models;
using Xunit;

namespace TqkLibrary.VpnClient.ZeroTier.Tests
{
    /// <summary>
    /// Self-pair seal/open and tamper-rejection for the VL1 Salsa20/12 + Poly1305 codec. Self-consistent and
    /// tamper-detecting offline; interop with a real zerotier-one peer is UNVERIFIED (VM lab down).
    /// </summary>
    public class Vl1PacketCodecTests
    {
        static byte[] Key()
        {
            byte[] k = new byte[32];
            for (int i = 0; i < k.Length; i++) k[i] = (byte)(i * 5 + 3);
            return k;
        }

        static Vl1Header NewHeader(Vl1Verb verb) => new Vl1Header
        {
            PacketId = 0x0123456789ABCDEFUL,
            Destination = ZeroTierAddress.Parse("8056c2e21c"),
            Source = ZeroTierAddress.Parse("deadbeef99"),
            Verb = verb,
        };

        readonly Vl1PacketCodec _codec = new Vl1PacketCodec();

        [Fact]
        public void SealThenOpen_RoundTrips_HeaderAndPayload()
        {
            byte[] key = Key();
            byte[] payload = System.Text.Encoding.ASCII.GetBytes("VL1 frame body over Salsa20/12");
            byte[] packet = _codec.Seal(NewHeader(Vl1Verb.Frame), key, payload);

            // The cipher field must record Salsa2012Poly1305, and the payload must not appear in the clear.
            Assert.Equal((int)Vl1CipherSuite.Salsa2012Poly1305, packet[18] & 0x07);
            Assert.True(_codec.Open(packet, key, out var header, out byte[] recovered));

            Assert.Equal(0x0123456789ABCDEFUL, header.PacketId);
            Assert.Equal(ZeroTierAddress.Parse("8056c2e21c"), header.Destination);
            Assert.Equal(ZeroTierAddress.Parse("deadbeef99"), header.Source);
            Assert.Equal(Vl1Verb.Frame, header.Verb);
            Assert.Equal(payload, recovered);
        }

        [Fact]
        public void Open_RejectsTamperedCiphertext()
        {
            byte[] key = Key();
            byte[] packet = _codec.Seal(NewHeader(Vl1Verb.Ok), key, new byte[] { 1, 2, 3, 4 });

            packet[Vl1Header.Size + 1] ^= 0xFF; // flip a ciphertext byte
            Assert.False(_codec.Open(packet, key, out _, out _));
        }

        [Fact]
        public void Open_RejectsTamperedMac()
        {
            byte[] key = Key();
            byte[] packet = _codec.Seal(NewHeader(Vl1Verb.Ok), key, new byte[] { 9, 8, 7 });

            packet[Vl1Header.MacOffset] ^= 0x01; // flip a MAC byte
            Assert.False(_codec.Open(packet, key, out _, out _));
        }

        [Fact]
        public void Open_RejectsWrongKey()
        {
            byte[] packet = _codec.Seal(NewHeader(Vl1Verb.Frame), Key(), new byte[] { 5, 5, 5 });
            byte[] otherKey = Key();
            otherKey[0] ^= 0x80;
            Assert.False(_codec.Open(packet, otherKey, out _, out _));
        }

        [Fact]
        public void EmptyPayload_RoundTrips()
        {
            byte[] key = Key();
            byte[] packet = _codec.Seal(NewHeader(Vl1Verb.Nop), key, ReadOnlySpan<byte>.Empty);
            Assert.True(_codec.Open(packet, key, out var header, out byte[] recovered));
            Assert.Equal(Vl1Verb.Nop, header.Verb);
            Assert.Empty(recovered);
        }
    }
}
