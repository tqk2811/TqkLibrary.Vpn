using System.Text;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Crypto.Aead;
using TqkLibrary.VpnClient.Crypto.Noise;
using Xunit;

namespace TqkLibrary.VpnClient.Crypto.Tests
{
    public class NoiseSymmetricStateTests
    {
        static readonly IPrf Prf = new HmacBlake2sPrf();
        static readonly IHashAlgo Hash = new Blake2s();
        static readonly IAeadCipher Cipher = new ChaCha20Poly1305Cipher();

        static NoiseSymmetricState NewState() => new NoiseSymmetricState(Prf, Hash, Cipher);

        static byte[] Hash32(byte[] input)
        {
            byte[] o = new byte[32];
            Hash.ComputeHash(input, o);
            return o;
        }

        // Intermediate WireGuard handshake vectors: ck0 = BLAKE2s(CONSTRUCTION), h0 = BLAKE2s(ck0 || IDENTIFIER).
        // These are the canonical reference WireGuard seeds (InitialChainKey / InitialHash) — verified live against a
        // real wg peer (V.3): the construction string is "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" (abbreviated cipher).
        const string ExpectedCk0 = "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36";
        const string ExpectedH0 = "2211b361081ac566691243db458ad5322d9c6c662293e8b70ee19c65ba079ef3";

        [Fact]
        public void InitializeWireGuard_MatchesDocumentedConstructionAndIdentifierHashes()
        {
            var s = NewState();
            s.InitializeWireGuard();

            Assert.Equal(ExpectedCk0, Convert.ToHexString(s.ChainingKey).ToLowerInvariant());
            Assert.Equal(ExpectedH0, Convert.ToHexString(s.HashValue).ToLowerInvariant());
            Assert.False(s.HasKey); // no key until MixKey/MixKeyAndHash
        }

        [Fact]
        public void InitializeWireGuard_EqualsInitializeSymmetricPlusMixHash()
        {
            // The WireGuard seed is exactly InitializeSymmetric(CONSTRUCTION) followed by MixHash(IDENTIFIER),
            // because the construction string is longer than HASHLEN (so InitializeSymmetric hashes it).
            var a = NewState();
            a.InitializeWireGuard();

            var b = NewState();
            b.InitializeSymmetric(Encoding.ASCII.GetBytes(NoiseSymmetricState.Construction));
            // After InitializeSymmetric, ck == h == HASH(construction).
            Assert.Equal(b.ChainingKey, b.HashValue);
            b.MixHash(Encoding.ASCII.GetBytes(NoiseSymmetricState.Identifier));

            Assert.Equal(a.ChainingKey, b.ChainingKey);
            Assert.Equal(a.HashValue, b.HashValue);
        }

        [Fact]
        public void InitializeSymmetric_ShortName_ZeroPadsIntoHashAndChainKey()
        {
            var s = NewState();
            byte[] name = Encoding.ASCII.GetBytes("short"); // <= 32 bytes
            s.InitializeSymmetric(name);

            byte[] expected = new byte[32];
            Array.Copy(name, expected, name.Length);
            Assert.Equal(expected, s.HashValue);
            Assert.Equal(expected, s.ChainingKey);
        }

        [Fact]
        public void MixHash_IsOrderSensitive_AndDeterministic()
        {
            byte[] a = Encoding.ASCII.GetBytes("alpha");
            byte[] b = Encoding.ASCII.GetBytes("bravo-segment");

            var s1 = NewState(); s1.InitializeWireGuard();
            s1.MixHash(a); s1.MixHash(b);

            var s2 = NewState(); s2.InitializeWireGuard();
            s2.MixHash(a); s2.MixHash(b);

            var s3 = NewState(); s3.InitializeWireGuard();
            s3.MixHash(b); s3.MixHash(a); // swapped order

            Assert.Equal(s1.HashValue, s2.HashValue);   // deterministic
            Assert.NotEqual(s1.HashValue, s3.HashValue); // order matters (h = HASH(h || data))
        }

        [Fact]
        public void MixHash_MatchesHashOfPreviousHashConcatData()
        {
            var s = NewState();
            s.InitializeWireGuard();
            byte[] before = s.HashValue;
            byte[] data = Encoding.ASCII.GetBytes("transcript chunk");

            byte[] cat = new byte[32 + data.Length];
            Array.Copy(before, 0, cat, 0, 32);
            Array.Copy(data, 0, cat, 32, data.Length);
            byte[] expected = Hash32(cat);

            s.MixHash(data);
            Assert.Equal(expected, s.HashValue);
        }

        [Fact]
        public void MixKey_AdvancesChainKey_SetsCipherKey_AndIsDeterministic()
        {
            byte[] ikm = Encoding.ASCII.GetBytes("dh-shared-secret-32-bytes-padded");

            var s1 = NewState(); s1.InitializeWireGuard();
            byte[] ckBefore = s1.ChainingKey;
            s1.MixKey(ikm);
            byte[] ckAfter = s1.ChainingKey;

            Assert.True(s1.HasKey);
            Assert.NotEqual(ckBefore, ckAfter); // chain key advanced

            var s2 = NewState(); s2.InitializeWireGuard();
            s2.MixKey(ikm);
            Assert.Equal(ckAfter, s2.ChainingKey); // deterministic given same seed + ikm
        }

        [Fact]
        public void EncryptAndHash_ThenDecryptAndHash_RoundTrips_OnTwinStates()
        {
            // Sender and receiver run the same symmetric transcript, so their keys + hash stay in lock-step.
            byte[] ikm = Encoding.ASCII.GetBytes("shared input keying material 32b");
            byte[] plaintext = Encoding.ASCII.GetBytes("static public key payload (32B)!");

            var sender = NewState(); sender.InitializeWireGuard(); sender.MixKey(ikm);
            var receiver = NewState(); receiver.InitializeWireGuard(); receiver.MixKey(ikm);

            byte[] sealed1 = sender.EncryptAndHash(plaintext);
            Assert.Equal(plaintext.Length + 16, sealed1.Length); // ciphertext || 16-byte tag

            byte[]? opened1 = receiver.DecryptAndHash(sealed1);
            Assert.NotNull(opened1);
            Assert.Equal(plaintext, opened1);

            // Hashes must have advanced identically (both mixed the same ciphertext).
            Assert.Equal(sender.HashValue, receiver.HashValue);

            // A second message uses nonce counter 1 — still must round-trip.
            byte[] plaintext2 = Encoding.ASCII.GetBytes("second");
            byte[] sealed2 = sender.EncryptAndHash(plaintext2);
            byte[]? opened2 = receiver.DecryptAndHash(sealed2);
            Assert.Equal(plaintext2, opened2);
            Assert.Equal(sender.HashValue, receiver.HashValue);
        }

        [Fact]
        public void DecryptAndHash_TamperedTag_ReturnsNull_AndLeavesStateUnchanged()
        {
            byte[] ikm = Encoding.ASCII.GetBytes("shared input keying material 32b");
            var sender = NewState(); sender.InitializeWireGuard(); sender.MixKey(ikm);
            var receiver = NewState(); receiver.InitializeWireGuard(); receiver.MixKey(ikm);

            byte[] sealedMsg = sender.EncryptAndHash(Encoding.ASCII.GetBytes("payload"));
            byte[] hashBefore = receiver.HashValue;

            byte[] tampered = (byte[])sealedMsg.Clone();
            tampered[^1] ^= 0xFF; // corrupt the tag

            Assert.Null(receiver.DecryptAndHash(tampered));
            Assert.Equal(hashBefore, receiver.HashValue); // no MixHash / nonce advance on failure

            // The valid message must still decrypt afterwards (state was not consumed by the failed attempt).
            Assert.NotNull(receiver.DecryptAndHash(sealedMsg));
        }

        [Fact]
        public void EncryptAndHash_WithoutKey_ReturnsPlaintextButStillMixesHash()
        {
            // Before any MixKey, EncryptAndHash is a no-op cipher (Noise prefix) but must still advance h.
            var s = NewState(); s.InitializeWireGuard();
            byte[] hBefore = s.HashValue;
            byte[] payload = Encoding.ASCII.GetBytes("ephemeral public key");

            byte[] outp = s.EncryptAndHash(payload);
            Assert.Equal(payload, outp);                 // verbatim, no tag
            Assert.NotEqual(hBefore, s.HashValue);       // hash advanced

            // The receiving side mirrors via DecryptAndHash and reaches the same hash.
            var r = NewState(); r.InitializeWireGuard();
            byte[]? back = r.DecryptAndHash(outp);
            Assert.Equal(payload, back);
            Assert.Equal(s.HashValue, r.HashValue);
        }

        [Fact]
        public void MixKeyAndHash_MixesPskIntoBothChainKeyAndHash()
        {
            byte[] psk = new byte[32];
            for (int i = 0; i < psk.Length; i++) psk[i] = (byte)(i + 1);

            var s = NewState(); s.InitializeWireGuard();
            byte[] ckBefore = s.ChainingKey;
            byte[] hBefore = s.HashValue;

            s.MixKeyAndHash(psk);

            Assert.True(s.HasKey);
            Assert.NotEqual(ckBefore, s.ChainingKey); // chain key advanced (KDF3 t1)
            Assert.NotEqual(hBefore, s.HashValue);     // hash mixed with t2

            // Deterministic.
            var s2 = NewState(); s2.InitializeWireGuard(); s2.MixKeyAndHash(psk);
            Assert.Equal(s.ChainingKey, s2.ChainingKey);
            Assert.Equal(s.HashValue, s2.HashValue);
        }

        [Fact]
        public void Split_ProducesTwoDistinct32ByteTransportKeys()
        {
            byte[] ikm = Encoding.ASCII.GetBytes("final dh of the handshake -- 32b");
            var s = NewState(); s.InitializeWireGuard(); s.MixKey(ikm);

            (byte[] first, byte[] second) = s.Split();
            Assert.Equal(32, first.Length);
            Assert.Equal(32, second.Length);
            Assert.NotEqual(first, second);

            // Initiator's (send, recv) is the responder's (recv, send): both derive the same pair from the same ck.
            var peer = NewState(); peer.InitializeWireGuard(); peer.MixKey(ikm);
            (byte[] pFirst, byte[] pSecond) = peer.Split();
            Assert.Equal(first, pFirst);
            Assert.Equal(second, pSecond);
        }

        [Fact]
        public void Constructor_RejectsWrongSizedPrimitives()
        {
            // A 20-byte PRF (HMAC-SHA1) is not a valid Noise SymmetricState PRF.
            var sha1Prf = new HmacPrf(System.Security.Cryptography.HashAlgorithmName.SHA1);
            Assert.Throws<ArgumentException>(() => new NoiseSymmetricState(sha1Prf, Hash, Cipher));
        }
    }
}
