using TqkLibrary.VpnClient.Tinc.Sptps;
using Xunit;

namespace TqkLibrary.VpnClient.Tinc.Tests
{
    /// <summary>Round-trip, tamper and replay-seqno behaviour of the tinc ChaCha-Poly1305 record cipher.</summary>
    public class TincChaChaPoly1305Tests
    {
        static byte[] Key()
        {
            byte[] k = new byte[TincChaChaPoly1305.KeyLength];
            for (int i = 0; i < k.Length; i++) k[i] = (byte)(i + 1);
            return k;
        }

        [Fact]
        public void EncryptDecrypt_RoundTrip()
        {
            var cipher = new TincChaChaPoly1305(Key());
            byte[] plaintext = System.Text.Encoding.ASCII.GetBytes("the quick brown fox jumps over the lazy dog");
            byte[] output = new byte[plaintext.Length + TincChaChaPoly1305.TagLength];
            cipher.Encrypt(42, plaintext, output);

            byte[] recovered = new byte[plaintext.Length];
            Assert.True(cipher.Decrypt(42, output, recovered));
            Assert.Equal(plaintext, recovered);
        }

        [Fact]
        public void Decrypt_WrongSeqno_Fails()
        {
            var cipher = new TincChaChaPoly1305(Key());
            byte[] plaintext = { 1, 2, 3, 4, 5 };
            byte[] output = new byte[plaintext.Length + TincChaChaPoly1305.TagLength];
            cipher.Encrypt(7, plaintext, output);

            byte[] recovered = new byte[plaintext.Length];
            Assert.False(cipher.Decrypt(8, output, recovered)); // different seqno → tag mismatch
        }

        [Fact]
        public void Decrypt_TamperedCiphertext_Fails()
        {
            var cipher = new TincChaChaPoly1305(Key());
            byte[] plaintext = { 9, 8, 7, 6 };
            byte[] output = new byte[plaintext.Length + TincChaChaPoly1305.TagLength];
            cipher.Encrypt(0, plaintext, output);
            output[1] ^= 0x80;

            byte[] recovered = new byte[plaintext.Length];
            Assert.False(cipher.Decrypt(0, output, recovered));
        }

        [Fact]
        public void Encrypt_EmptyPayload_RoundTrips()
        {
            var cipher = new TincChaChaPoly1305(Key());
            byte[] output = new byte[TincChaChaPoly1305.TagLength];
            cipher.Encrypt(123, ReadOnlySpan<byte>.Empty, output);
            byte[] recovered = Array.Empty<byte>();
            Assert.True(cipher.Decrypt(123, output, recovered));
        }
    }
}
