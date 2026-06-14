using TqkLibrary.VpnClient.Ipsec.Esp;
using Xunit;

namespace TqkLibrary.VpnClient.Ipsec.Esp.Tests
{
    public class EspTransformTests
    {
        const uint SpiAToB = 0xAABBCCDD;
        const uint SpiBToA = 0x11223344;

        static (EspSession a, EspSession b) PairCbc()
        {
            byte[] encAb = Fill(32, 0x01), integAb = Fill(32, 0x02);
            byte[] encBa = Fill(32, 0x03), integBa = Fill(32, 0x04);
            EspCipherSuite aToB = EspCipherSuite.AesCbcHmacSha256(encAb, integAb);
            EspCipherSuite bToA = EspCipherSuite.AesCbcHmacSha256(encBa, integBa);
            var a = new EspSession(SpiAToB, aToB, SpiBToA, bToA);
            var b = new EspSession(SpiBToA, bToA, SpiAToB, aToB);
            return (a, b);
        }

        static (EspSession a, EspSession b) PairGcm()
        {
            byte[] keyAb = Fill(16, 0x10), saltAb = Fill(4, 0x1A);
            byte[] keyBa = Fill(16, 0x20), saltBa = Fill(4, 0x2A);
            EspCipherSuite aToB = EspCipherSuite.AesGcm(keyAb, saltAb);
            EspCipherSuite bToA = EspCipherSuite.AesGcm(keyBa, saltBa);
            var a = new EspSession(SpiAToB, aToB, SpiBToA, bToA);
            var b = new EspSession(SpiBToA, bToA, SpiAToB, aToB);
            return (a, b);
        }

        static byte[] Fill(int n, byte seed)
        {
            byte[] b = new byte[n];
            for (int i = 0; i < n; i++) b[i] = (byte)(seed + i);
            return b;
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(13)]
        [InlineData(14)]
        [InlineData(15)]
        [InlineData(16)]
        [InlineData(17)]
        [InlineData(100)]
        [InlineData(1400)]
        public void Cbc_RoundTrip_RecoversPayload(int length)
        {
            (EspSession a, EspSession b) = PairCbc();
            byte[] payload = Fill(length, 0x55);

            byte[] packet = a.Protect(payload, EspConstants.NextHeaderUdp);
            Assert.True(b.TryUnprotect(packet, out byte[] recovered, out byte nextHeader));

            Assert.Equal(payload, recovered);
            Assert.Equal(EspConstants.NextHeaderUdp, nextHeader);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(15)]
        [InlineData(16)]
        [InlineData(100)]
        [InlineData(1400)]
        public void Gcm_RoundTrip_RecoversPayload(int length)
        {
            (EspSession a, EspSession b) = PairGcm();
            byte[] payload = Fill(length, 0x77);

            byte[] packet = a.Protect(payload, EspConstants.NextHeaderUdp);
            Assert.True(b.TryUnprotect(packet, out byte[] recovered, out byte nextHeader));

            Assert.Equal(payload, recovered);
            Assert.Equal(EspConstants.NextHeaderUdp, nextHeader);
        }

        [Fact]
        public void Cbc_SequenceNumbers_StartAtOneAndIncrement()
        {
            (EspSession a, _) = PairCbc();
            byte[] p1 = a.Protect(Fill(8, 0), EspConstants.NextHeaderUdp);
            byte[] p2 = a.Protect(Fill(8, 0), EspConstants.NextHeaderUdp);
            Assert.Equal(1u, EspConstants.ReadSequence(p1));
            Assert.Equal(2u, EspConstants.ReadSequence(p2));
            Assert.Equal(SpiAToB, EspConstants.ReadSpi(p1));
        }

        [Fact]
        public void Cbc_TamperedCiphertext_FailsIntegrity()
        {
            (EspSession a, EspSession b) = PairCbc();
            byte[] packet = a.Protect(Fill(40, 0x33), EspConstants.NextHeaderUdp);
            packet[EspConstants.HeaderSize + 16 + 4] ^= 0xFF; // flip a ciphertext byte
            Assert.False(b.TryUnprotect(packet, out _, out _));
        }

        [Fact]
        public void Cbc_TamperedIcv_FailsIntegrity()
        {
            (EspSession a, EspSession b) = PairCbc();
            byte[] packet = a.Protect(Fill(40, 0x33), EspConstants.NextHeaderUdp);
            packet[^1] ^= 0xFF; // flip the last ICV byte
            Assert.False(b.TryUnprotect(packet, out _, out _));
        }

        [Fact]
        public void Gcm_TamperedTag_FailsAuthentication()
        {
            (EspSession a, EspSession b) = PairGcm();
            byte[] packet = a.Protect(Fill(40, 0x44), EspConstants.NextHeaderUdp);
            packet[^1] ^= 0xFF;
            Assert.False(b.TryUnprotect(packet, out _, out _));
        }

        [Fact]
        public void WrongSpi_IsRejected()
        {
            (EspSession a, EspSession b) = PairCbc();
            byte[] packet = b.Protect(Fill(16, 0x66), EspConstants.NextHeaderUdp); // B→A SPI
            // Feed a B-origin packet back to B: SPI does not match B's inbound SA.
            Assert.False(b.TryUnprotect(packet, out _, out _));
        }

        [Fact]
        public void Replay_OfSamePacket_IsRejected()
        {
            (EspSession a, EspSession b) = PairCbc();
            byte[] packet = a.Protect(Fill(20, 0x99), EspConstants.NextHeaderUdp);
            Assert.True(b.TryUnprotect(packet, out _, out _));
            Assert.False(b.TryUnprotect(packet, out _, out _)); // same sequence again → replay
        }

        [Fact]
        public void OutOfOrder_WithinWindow_IsAccepted()
        {
            (EspSession a, EspSession b) = PairCbc();
            byte[] p1 = a.Protect(Fill(8, 1), EspConstants.NextHeaderUdp); // seq 1
            byte[] p2 = a.Protect(Fill(8, 2), EspConstants.NextHeaderUdp); // seq 2
            byte[] p3 = a.Protect(Fill(8, 3), EspConstants.NextHeaderUdp); // seq 3

            Assert.True(b.TryUnprotect(p3, out _, out _)); // deliver 3 first
            Assert.True(b.TryUnprotect(p1, out _, out _)); // then 1 (within window)
            Assert.True(b.TryUnprotect(p2, out _, out _)); // then 2
            Assert.False(b.TryUnprotect(p2, out _, out _)); // 2 again → replay
        }
    }
}
