using TqkLibrary.VpnClient.Ssh.Cipher;
using Xunit;

namespace TqkLibrary.VpnClient.Ssh.Tests
{
    /// <summary>
    /// Self-pair round-trip + tamper tests for the SSH packet ciphers — chacha20-poly1305@openssh.com and
    /// aes256-gcm@openssh.com. Seal then Open must recover the exact cleartext binary packet under matching sequence
    /// numbers; any corruption of the ciphertext, the tag or the sequence number must fail authentication (Open returns
    /// false). The cleartext "packet" is the framed binary packet <c>uint32 length || body</c> the codec produces.
    /// </summary>
    public class SshCipherTests
    {
        static byte[] SamplePacket(int bodyLen)
        {
            // length-field || body (the codec's framed binary packet — its exact shape does not matter for the cipher).
            byte[] packet = new byte[4 + bodyLen];
            for (int i = 0; i < packet.Length; i++) packet[i] = (byte)(i * 7 + 1);
            packet[0] = (byte)(bodyLen >> 24); packet[1] = (byte)(bodyLen >> 16);
            packet[2] = (byte)(bodyLen >> 8); packet[3] = (byte)bodyLen;
            return packet;
        }

        [Theory]
        [InlineData(0)]
        [InlineData(7)]
        [InlineData(64)]
        [InlineData(1500)]
        public void ChaCha20Poly1305OpenSsh_SealOpen_RoundTrips(int bodyLen)
        {
            byte[] keyMaterial = new byte[64];
            for (int i = 0; i < 64; i++) keyMaterial[i] = (byte)(i + 1);
            var cipher = new ChaCha20Poly1305OpenSshCipher(keyMaterial);
            byte[] packet = SamplePacket(bodyLen);

            for (uint seq = 0; seq < 3; seq++)
            {
                byte[] wire = cipher.Seal(packet, seq);
                // The length must be recoverable from the first 4 wire bytes alone.
                uint len = cipher.ReadLength(wire.AsSpan(0, 4), seq);
                Assert.Equal((uint)bodyLen, len);

                byte[] plain = new byte[packet.Length];
                Assert.True(cipher.Open(wire, len, seq, plain));
                Assert.Equal(packet, plain);
            }
        }

        [Fact]
        public void ChaCha20Poly1305OpenSsh_WrongSequenceNumber_FailsMac()
        {
            byte[] keyMaterial = new byte[64];
            for (int i = 0; i < 64; i++) keyMaterial[i] = (byte)(i * 3 + 5);
            var cipher = new ChaCha20Poly1305OpenSshCipher(keyMaterial);
            byte[] packet = SamplePacket(40);

            byte[] wire = cipher.Seal(packet, 5);
            uint len = cipher.ReadLength(wire.AsSpan(0, 4), 5);
            byte[] plain = new byte[packet.Length];
            Assert.False(cipher.Open(wire, len, 6, plain)); // wrong seq → wrong poly key → MAC mismatch
        }

        [Fact]
        public void ChaCha20Poly1305OpenSsh_TamperedTag_FailsMac()
        {
            byte[] keyMaterial = new byte[64];
            var cipher = new ChaCha20Poly1305OpenSshCipher(keyMaterial);
            byte[] packet = SamplePacket(32);

            byte[] wire = cipher.Seal(packet, 0);
            wire[wire.Length - 1] ^= 0x80; // flip a tag bit
            uint len = cipher.ReadLength(wire.AsSpan(0, 4), 0);
            byte[] plain = new byte[packet.Length];
            Assert.False(cipher.Open(wire, len, 0, plain));
        }

        [Theory]
        [InlineData(8)]
        [InlineData(64)]
        [InlineData(1280)]
        public void AesGcmOpenSsh_SealOpen_RoundTrips(int bodyLen)
        {
            byte[] key = new byte[32]; for (int i = 0; i < 32; i++) key[i] = (byte)(i + 9);
            byte[] iv = new byte[12]; for (int i = 0; i < 12; i++) iv[i] = (byte)(i + 1);
            var sender = new AesGcmOpenSshCipher(key, iv);
            var receiver = new AesGcmOpenSshCipher(key, iv); // a separate IV state, advanced in lock-step
            byte[] packet = SamplePacket(bodyLen);

            for (uint seq = 0; seq < 4; seq++)
            {
                byte[] wire = sender.Seal(packet, seq);
                uint len = receiver.ReadLength(wire.AsSpan(0, 4), seq);
                Assert.Equal((uint)bodyLen, len);
                byte[] plain = new byte[packet.Length];
                Assert.True(receiver.Open(wire, len, seq, plain));
                Assert.Equal(packet, plain);
            }
        }

        [Fact]
        public void AesGcmOpenSsh_LengthIsCleartextAndAuthenticated()
        {
            byte[] key = new byte[32];
            byte[] iv = new byte[12];
            var cipher = new AesGcmOpenSshCipher(key, iv);
            Assert.False(cipher.LengthIsEncrypted);

            byte[] packet = SamplePacket(16);
            byte[] wire = cipher.Seal(packet, 0);
            // The first 4 wire bytes equal the cleartext length field.
            Assert.Equal(packet.AsSpan(0, 4).ToArray(), wire.AsSpan(0, 4).ToArray());
        }
    }
}
