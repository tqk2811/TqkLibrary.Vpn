using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
#if NET5_0_OR_GREATER
using System.Security.Cryptography;
#else
// Alias specific types (not the whole namespace) so BouncyCastle's own IAeadCipher does not clash with ours.
using ChaCha20Poly1305Engine = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;
using AeadParameters = Org.BouncyCastle.Crypto.Parameters.AeadParameters;
using KeyParameter = Org.BouncyCastle.Crypto.Parameters.KeyParameter;
#endif

namespace TqkLibrary.VpnClient.Crypto.Aead
{
    /// <summary>
    /// ChaCha20-Poly1305 AEAD (RFC 8439). Uses the native <c>ChaCha20Poly1305</c> on .NET 5+ (net8.0 in this build) and
    /// a BouncyCastle fallback on netstandard2.0 (where the BCL has no ChaCha20-Poly1305). Fixed sizes: 32-byte key,
    /// 12-byte nonce, 16-byte tag — the same shape as AES-256-GCM, so OpenVPN's data channel treats them identically.
    /// </summary>
    public sealed class ChaCha20Poly1305Cipher : IAeadCipher
    {
        const int KeyBytes = 32;
        const int TagBytes = 16;
        const int NonceBytes = 12;

        /// <inheritdoc/>
        public int KeySizeInBytes => KeyBytes;

        /// <inheritdoc/>
        public int NonceSizeInBytes => NonceBytes;

        /// <inheritdoc/>
        public int TagSizeInBytes => TagBytes;

        /// <inheritdoc/>
        public void Seal(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> associatedData,
            Span<byte> ciphertext,
            Span<byte> tag)
        {
#if NET5_0_OR_GREATER
            using var aead = new ChaCha20Poly1305(key);
            aead.Encrypt(nonce, plaintext, ciphertext.Slice(0, plaintext.Length), tag.Slice(0, TagBytes), associatedData);
#else
            var cipher = new ChaCha20Poly1305Engine();
            cipher.Init(true, new AeadParameters(new KeyParameter(key.ToArray()), TagBytes * 8, nonce.ToArray(), associatedData.ToArray()));
            byte[] input = plaintext.ToArray();
            byte[] output = new byte[cipher.GetOutputSize(input.Length)];
            int len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
            cipher.DoFinal(output, len);
            // output = ciphertext || tag
            output.AsSpan(0, plaintext.Length).CopyTo(ciphertext);
            output.AsSpan(plaintext.Length, TagBytes).CopyTo(tag);
#endif
        }

        /// <inheritdoc/>
        public bool Open(
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            ReadOnlySpan<byte> associatedData,
            Span<byte> plaintext)
        {
#if NET5_0_OR_GREATER
            try
            {
                using var aead = new ChaCha20Poly1305(key);
                aead.Decrypt(nonce, ciphertext, tag.Slice(0, TagBytes), plaintext.Slice(0, ciphertext.Length), associatedData);
                return true;
            }
            catch (AuthenticationTagMismatchException)
            {
                return false;
            }
#else
            var cipher = new ChaCha20Poly1305Engine();
            cipher.Init(false, new AeadParameters(new KeyParameter(key.ToArray()), TagBytes * 8, nonce.ToArray(), associatedData.ToArray()));
            byte[] input = new byte[ciphertext.Length + TagBytes];
            ciphertext.CopyTo(input);
            tag.Slice(0, TagBytes).CopyTo(input.AsSpan(ciphertext.Length));
            byte[] output = new byte[cipher.GetOutputSize(input.Length)];
            try
            {
                int len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
                len += cipher.DoFinal(output, len);
                output.AsSpan(0, len).CopyTo(plaintext);
                return true;
            }
            catch (Org.BouncyCastle.Crypto.InvalidCipherTextException)
            {
                return false;
            }
#endif
        }
    }
}
