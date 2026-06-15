using TqkLibrary.VpnClient.Crypto.Aead;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    public class ChaCha20Poly1305CipherTests
    {
        // RFC 8439 §2.8.2 AEAD_CHACHA20_POLY1305 test vector.
        [Fact]
        public void ChaCha20Poly1305_SealMatchesRfc8439Vector()
        {
            byte[] key = Convert.FromHexString("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
            byte[] nonce = Convert.FromHexString("070000004041424344454647");
            byte[] plaintext = Convert.FromHexString(
                "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
                "73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
                "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
                "637265656e20776f756c642062652069742e");
            byte[] aad = Convert.FromHexString("50515253c0c1c2c3c4c5c6c7");
            byte[] expectedCt = Convert.FromHexString(
                "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
                "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
                "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
                "3ff4def08e4b7a9de576d26586cec64b6116");
            byte[] expectedTag = Convert.FromHexString("1ae10b594f09e26a7e902ecbd0600691");

            var cipher = new ChaCha20Poly1305Cipher();
            byte[] ct = new byte[plaintext.Length];
            byte[] tag = new byte[cipher.TagSizeInBytes];
            cipher.Seal(key, nonce, plaintext, aad, ct, tag);

            Assert.Equal(expectedCt, ct);
            Assert.Equal(expectedTag, tag);
        }

        [Fact]
        public void ChaCha20Poly1305_OpenRoundtripsAndDetectsTamper()
        {
            byte[] key = Convert.FromHexString("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
            byte[] nonce = Convert.FromHexString("070000004041424344454647");
            byte[] plaintext = Convert.FromHexString("4c616469657320616e642047656e746c656d656e");
            byte[] aad = Convert.FromHexString("50515253c0c1c2c3");

            var cipher = new ChaCha20Poly1305Cipher();
            byte[] ct = new byte[plaintext.Length];
            byte[] tag = new byte[cipher.TagSizeInBytes];
            cipher.Seal(key, nonce, plaintext, aad, ct, tag);

            byte[] recovered = new byte[plaintext.Length];
            Assert.True(cipher.Open(key, nonce, ct, tag, aad, recovered));
            Assert.Equal(plaintext, recovered);

            // Flip a tag bit -> authentication must fail.
            tag[0] ^= 0x01;
            Assert.False(cipher.Open(key, nonce, ct, tag, aad, recovered));
        }
    }
}
