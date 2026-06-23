using System.Text;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.VpnClient.Crypto.Noise
{
    /// <summary>
    /// The Noise protocol <c>SymmetricState</c> (Noise spec §5.2) specialised for WireGuard's
    /// <c>Noise_IKpsk2_25519_ChaCha20Poly1305_BLAKE2s</c> handshake. It tracks the running transcript hash
    /// (<c>h</c>), the chaining key (<c>ck</c>) and an optional cipher key (<c>k</c>) with a 64-bit message counter,
    /// driving the symmetric half of the handshake while the caller supplies the DH results.
    /// <para>
    /// Reuses the F.4 primitives unchanged: BLAKE2s (<see cref="IHashAlgo"/>) for <see cref="MixHash"/>, the
    /// Noise/WireGuard KDF (<see cref="NoiseKdf"/> over HMAC-BLAKE2s <see cref="IPrf"/>) for <see cref="MixKey"/> /
    /// <see cref="MixKeyAndHash"/> / <see cref="Split"/>, and ChaCha20-Poly1305 (<see cref="IAeadCipher"/>) for
    /// <see cref="EncryptAndHash"/> / <see cref="DecryptAndHash"/>. WireGuard fixes HASHLEN = DHLEN = 32 and uses an
    /// AEAD nonce of <c>0^4 || counter</c> (4 zero bytes then the 64-bit counter little-endian) with the current
    /// transcript hash <c>h</c> as the associated data.
    /// </para>
    /// </summary>
    public sealed class NoiseSymmetricState
    {
        /// <summary>WireGuard handshake construction string — hashed to seed the chaining key (and the transcript hash).
        /// This is the <b>exact</b> string the reference WireGuard implementations hash (wireguard-go
        /// <c>NoiseConstruction</c> / the kernel module): the cipher is abbreviated <c>ChaChaPoly</c>, <b>not</b> the
        /// fully-spelt Noise protocol name <c>ChaCha20Poly1305</c>. Getting this wrong still self-interops (both ends
        /// seed the same wrong <c>ck0</c>/<c>h0</c>) but a real <c>wg</c> peer rejects the initiation
        /// ("invalid initiation message") because its transcript hash diverges — only verified live (lab Q.1, V.3).</summary>
        public const string Construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";

        /// <summary>WireGuard identifier string — mixed into the transcript hash right after initialisation.</summary>
        public const string Identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com";

        const int HashLen = 32;  // BLAKE2s-256 digest / chaining-key length
        const int KeyLen = 32;   // ChaCha20-Poly1305 key length

        readonly IPrf _prf;
        readonly IHashAlgo _hash;
        readonly IAeadCipher _cipher;

        readonly byte[] _chainingKey = new byte[HashLen];
        readonly byte[] _hashValue = new byte[HashLen];
        readonly byte[] _cipherKey = new byte[KeyLen];
        bool _hasKey;
        ulong _nonce;

        /// <summary>
        /// Creates a symmetric state over the supplied primitives. For WireGuard pass
        /// <see cref="HmacBlake2sPrf"/>, <see cref="Blake2s"/> and <see cref="ChaCha20Poly1305Cipher"/>
        /// (the cipher's key/nonce/tag must be 32/12/16 bytes). The state is not usable until
        /// <see cref="InitializeWireGuard"/> (or <see cref="InitializeSymmetric"/>) is called.
        /// </summary>
        public NoiseSymmetricState(IPrf prf, IHashAlgo hash, IAeadCipher cipher)
        {
            _prf = prf ?? throw new ArgumentNullException(nameof(prf));
            _hash = hash ?? throw new ArgumentNullException(nameof(hash));
            _cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
            if (prf.OutputSizeInBytes != HashLen)
                throw new ArgumentException("Noise SymmetricState requires a 32-byte PRF (HMAC-BLAKE2s).", nameof(prf));
            if (hash.HashSizeInBytes != HashLen)
                throw new ArgumentException("Noise SymmetricState requires a 32-byte hash (BLAKE2s-256).", nameof(hash));
            if (cipher.KeySizeInBytes != KeyLen || cipher.NonceSizeInBytes != 12 || cipher.TagSizeInBytes != 16)
                throw new ArgumentException("Noise SymmetricState requires ChaCha20-Poly1305 (key 32, nonce 12, tag 16).", nameof(cipher));
        }

        /// <summary>Current chaining key (32 bytes). Returns a copy.</summary>
        public byte[] ChainingKey => (byte[])_chainingKey.Clone();

        /// <summary>Current transcript hash <c>h</c> (32 bytes). Returns a copy.</summary>
        public byte[] HashValue => (byte[])_hashValue.Clone();

        /// <summary>Whether a cipher key has been established (<see cref="MixKey"/>/<see cref="MixKeyAndHash"/> was called).</summary>
        public bool HasKey => _hasKey;

        /// <summary>
        /// Noise <c>InitializeSymmetric</c> (spec §5.2): with a protocol name longer than HASHLEN (WireGuard's is),
        /// sets <c>h = ck = HASH(protocolName)</c>; with a shorter name it is zero-padded into <c>h</c>. Clears the
        /// cipher key. Use <see cref="InitializeWireGuard"/> for the full WireGuard seed (name + identifier).
        /// </summary>
        public void InitializeSymmetric(ReadOnlySpan<byte> protocolName)
        {
            if (protocolName.Length <= HashLen)
            {
                _hashValue.AsSpan().Clear();
                protocolName.CopyTo(_hashValue);
            }
            else
            {
                _hash.ComputeHash(protocolName, _hashValue);
            }
            _hashValue.AsSpan(0, HashLen).CopyTo(_chainingKey);
            _hasKey = false;
            _nonce = 0;
            _cipherKey.AsSpan().Clear();
        }

        /// <summary>
        /// WireGuard handshake seed: <c>ck = HASH(<see cref="Construction"/>)</c> then
        /// <c>h = HASH(ck || <see cref="Identifier"/>)</c> (equivalent to <see cref="InitializeSymmetric"/> on the
        /// construction string followed by <see cref="MixHash"/> of the identifier — the construction is &gt; 32 bytes).
        /// </summary>
        public void InitializeWireGuard()
        {
            InitializeSymmetric(Encoding.ASCII.GetBytes(Construction));
            MixHash(Encoding.ASCII.GetBytes(Identifier));
        }

        /// <summary>Noise <c>MixHash</c>: <c>h = HASH(h || data)</c>.</summary>
        public void MixHash(ReadOnlySpan<byte> data)
        {
            byte[] buffer = new byte[HashLen + data.Length];
            _hashValue.AsSpan(0, HashLen).CopyTo(buffer);
            data.CopyTo(buffer.AsSpan(HashLen));
            _hash.ComputeHash(buffer, _hashValue);
        }

        /// <summary>
        /// Noise <c>MixKey</c>: <c>(ck, k) = KDF2(ck, inputKeyMaterial)</c> (HMAC-BLAKE2s, <see cref="NoiseKdf.Kdf2"/>).
        /// Advances the chaining key and installs a fresh cipher key, resetting the nonce.
        /// </summary>
        public void MixKey(ReadOnlySpan<byte> inputKeyMaterial)
        {
            (byte[] ck, byte[] k) = NoiseKdf.Kdf2(_prf, _chainingKey, inputKeyMaterial);
            ck.AsSpan(0, HashLen).CopyTo(_chainingKey);
            InitializeKey(k);
        }

        /// <summary>
        /// Noise <c>MixKeyAndHash</c> (used for the WireGuard PSK): <c>(ck, t, k) = KDF3(ck, inputKeyMaterial)</c>
        /// (<see cref="NoiseKdf.Kdf3"/>), then <c>MixHash(t)</c> and a fresh cipher key. Mixes secret material into
        /// both the chaining key and the transcript hash.
        /// </summary>
        public void MixKeyAndHash(ReadOnlySpan<byte> inputKeyMaterial)
        {
            (byte[] ck, byte[] t, byte[] k) = NoiseKdf.Kdf3(_prf, _chainingKey, inputKeyMaterial);
            ck.AsSpan(0, HashLen).CopyTo(_chainingKey);
            MixHash(t);
            InitializeKey(k);
        }

        /// <summary>
        /// Noise <c>EncryptAndHash</c>: AEAD-seals <paramref name="plaintext"/> under the current key with
        /// nonce = <c>0^4 || counter</c> and AAD = current <c>h</c>, then <c>MixHash</c> over the resulting
        /// ciphertext+tag. Returns <c>ciphertext || tag</c> (16 bytes longer than the plaintext). If no key is set
        /// the plaintext is returned as-is and only mixed into the hash (Noise behaviour for the keyless prefix).
        /// </summary>
        public byte[] EncryptAndHash(ReadOnlySpan<byte> plaintext)
        {
            if (!_hasKey)
            {
                byte[] copy = plaintext.ToArray();
                MixHash(copy);
                return copy;
            }

            byte[] output = new byte[plaintext.Length + _cipher.TagSizeInBytes];
            Span<byte> nonce = stackalloc byte[_cipher.NonceSizeInBytes];
            WriteNonce(nonce);
            _cipher.Seal(_cipherKey, nonce, plaintext, _hashValue, output.AsSpan(0, plaintext.Length), output.AsSpan(plaintext.Length));
            _nonce++;
            MixHash(output);
            return output;
        }

        /// <summary>
        /// Noise <c>DecryptAndHash</c>: AEAD-opens <paramref name="ciphertextAndTag"/> (ciphertext || 16-byte tag)
        /// under the current key with nonce = <c>0^4 || counter</c> and AAD = current <c>h</c>. On success returns
        /// the plaintext and mixes the ciphertext into <c>h</c>; on authentication failure returns <c>null</c> and
        /// leaves the state unchanged. With no key set, the input is returned verbatim and mixed into the hash.
        /// </summary>
        public byte[]? DecryptAndHash(ReadOnlySpan<byte> ciphertextAndTag)
        {
            if (!_hasKey)
            {
                byte[] copy = ciphertextAndTag.ToArray();
                MixHash(copy);
                return copy;
            }

            int tagSize = _cipher.TagSizeInBytes;
            if (ciphertextAndTag.Length < tagSize) return null;
            int plainLen = ciphertextAndTag.Length - tagSize;

            // Snapshot the AAD (current h) before mixing, and only advance the nonce/hash if the tag verifies.
            byte[] aad = _hashValue.AsSpan(0, HashLen).ToArray();
            byte[] plaintext = new byte[plainLen];
            Span<byte> nonce = stackalloc byte[_cipher.NonceSizeInBytes];
            WriteNonce(nonce);
            bool ok = _cipher.Open(
                _cipherKey, nonce,
                ciphertextAndTag.Slice(0, plainLen), ciphertextAndTag.Slice(plainLen, tagSize),
                aad, plaintext);
            if (!ok) return null;

            _nonce++;
            MixHash(ciphertextAndTag);
            return plaintext;
        }

        /// <summary>
        /// Noise <c>Split</c>: derives the pair of transport keys <c>(T_send, T_recv) = KDF2(ck, empty)</c>
        /// (<see cref="NoiseKdf.Kdf2"/>). For the WireGuard initiator the first key encrypts outbound data and the
        /// second decrypts inbound; the responder swaps them. Each key is 32 bytes.
        /// </summary>
        public (byte[] FirstKey, byte[] SecondKey) Split()
        {
            (byte[] t1, byte[] t2) = NoiseKdf.Kdf2(_prf, _chainingKey, ReadOnlySpan<byte>.Empty);
            return (t1, t2);
        }

        void InitializeKey(ReadOnlySpan<byte> key)
        {
            key.Slice(0, KeyLen).CopyTo(_cipherKey);
            _hasKey = true;
            _nonce = 0;
        }

        // WireGuard AEAD nonce: 4 zero bytes followed by the 64-bit message counter, little-endian (12 bytes total).
        void WriteNonce(Span<byte> nonce)
        {
            nonce.Clear();
            ulong counter = _nonce;
            for (int i = 0; i < 8; i++)
                nonce[4 + i] = (byte)(counter >> (8 * i));
        }
    }
}
