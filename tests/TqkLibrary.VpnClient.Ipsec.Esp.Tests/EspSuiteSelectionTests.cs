using TqkLibrary.VpnClient.Ipsec.Esp;
using TqkLibrary.VpnClient.Ipsec.Esp.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Ipsec.Esp.Tests
{
    /// <summary>
    /// Pins <see cref="EspSuiteSelection"/>: the per-algorithm key-material lengths it advertises and that
    /// <see cref="EspSuiteSelection.BuildSuite"/> produces interoperable <see cref="EspCipherSuite"/>s for both
    /// directions. This is the single mapping IKEv1/IKEv2 rely on after negotiating a suite.
    /// </summary>
    public class EspSuiteSelectionTests
    {
        const uint SpiAToB = 0xAABBCCDD;
        const uint SpiBToA = 0x11223344;

        [Fact]
        public void AesCbcHmacSha1_Has32ByteKeyAnd20ByteIntegrity()
        {
            EspSuiteSelection s = EspSuiteSelection.AesCbcHmacSha1();
            Assert.Equal(EspEncryptionAlgorithm.AesCbc, s.Algorithm);
            Assert.Equal(32, s.EncryptionKeyLengthBytes);
            Assert.Equal(20, s.SecondSliceLengthBytes);
            Assert.Equal(52, s.KeyMaterialLengthPerDirection);
        }

        [Fact]
        public void AesCbcHmacSha256_Has32ByteKeyAnd32ByteIntegrity()
        {
            EspSuiteSelection s = EspSuiteSelection.AesCbcHmacSha256();
            Assert.Equal(EspEncryptionAlgorithm.AesCbc, s.Algorithm);
            Assert.Equal(32, s.EncryptionKeyLengthBytes);
            Assert.Equal(32, s.SecondSliceLengthBytes);
            Assert.Equal(64, s.KeyMaterialLengthPerDirection);
        }

        [Fact]
        public void AesGcm16_Has32ByteKeyAnd4ByteSalt()
        {
            EspSuiteSelection s = EspSuiteSelection.AesGcm16();
            Assert.Equal(EspEncryptionAlgorithm.AesGcm16, s.Algorithm);
            Assert.Equal(32, s.EncryptionKeyLengthBytes);
            Assert.Equal(4, s.SecondSliceLengthBytes);
            Assert.Equal(36, s.KeyMaterialLengthPerDirection);
        }

        [Fact]
        public void AesGcm16_WithAes128Key_Allowed()
        {
            EspSuiteSelection s = EspSuiteSelection.AesGcm16(16);
            Assert.Equal(16, s.EncryptionKeyLengthBytes);
            Assert.Equal(20, s.KeyMaterialLengthPerDirection);
        }

        [Fact]
        public void Factories_RejectInvalidAesKeyLength()
        {
            Assert.Throws<System.ArgumentException>(() => EspSuiteSelection.AesCbcHmacSha1(20));
            Assert.Throws<System.ArgumentException>(() => EspSuiteSelection.AesGcm16(20));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(15)]
        [InlineData(16)]
        [InlineData(100)]
        [InlineData(1400)]
        public void BuildSuite_AesCbcSha1_RoundTrips(int length)
            => RoundTrip(EspSuiteSelection.AesCbcHmacSha1(), length);

        [Theory]
        [InlineData(0)]
        [InlineData(16)]
        [InlineData(100)]
        [InlineData(1400)]
        public void BuildSuite_AesCbcSha256_RoundTrips(int length)
            => RoundTrip(EspSuiteSelection.AesCbcHmacSha256(), length);

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(16)]
        [InlineData(100)]
        [InlineData(1400)]
        public void BuildSuite_AesGcm_RoundTrips(int length)
            => RoundTrip(EspSuiteSelection.AesGcm16(), length);

        // Builds both directions with the selection and confirms one side encrypts and the other recovers the payload.
        static void RoundTrip(EspSuiteSelection selection, int length)
        {
            byte[] encAb = Fill(selection.EncryptionKeyLengthBytes, 0x10);
            byte[] secAb = Fill(selection.SecondSliceLengthBytes, 0x1A);
            byte[] encBa = Fill(selection.EncryptionKeyLengthBytes, 0x20);
            byte[] secBa = Fill(selection.SecondSliceLengthBytes, 0x2A);

            EspCipherSuite aToB = selection.BuildSuite(encAb, secAb);
            EspCipherSuite bToA = selection.BuildSuite(encBa, secBa);
            var a = new EspSession(SpiAToB, aToB, SpiBToA, bToA);
            var b = new EspSession(SpiBToA, bToA, SpiAToB, aToB);

            byte[] payload = Fill(length, 0x55);
            byte[] packet = a.Protect(payload, EspConstants.NextHeaderUdp);
            Assert.True(b.TryUnprotect(packet, out byte[] recovered, out byte nextHeader));
            Assert.Equal(payload, recovered);
            Assert.Equal(EspConstants.NextHeaderUdp, nextHeader);
        }

        static byte[] Fill(int n, byte seed)
        {
            byte[] b = new byte[n];
            for (int i = 0; i < n; i++) b[i] = (byte)(seed + i);
            return b;
        }
    }
}
