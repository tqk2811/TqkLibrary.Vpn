using System.Text;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.Tinc.Sptps.Models;

namespace TqkLibrary.VpnClient.Tinc.Sptps
{
    /// <summary>
    /// Drives one side of the tinc SPTPS handshake (the modern Ed25519/Curve25519 cipher suite) for a single session,
    /// reusing <see cref="SptpsEcdh"/> for the ephemeral (Ed25519-keyed) ECDH and <see cref="Ed25519Signer"/> for the
    /// authentication signature — no crypto is reimplemented here. The class only sequences KEX → SIG, builds the
    /// signed transcript and the KDF seed exactly as tinc's <c>sptps.c</c>, and derives the directional record keys.
    /// <para>
    /// Handshake (initiator perspective): send <b>KEX</b> (version‖nonce‖ephemeral-pubkey); receive peer KEX; derive
    /// the shared secret and key material; send <b>SIG</b> (Ed25519 over <c>initiator_flag ‖ my_kex ‖ his_kex ‖
    /// label</c>); receive and verify the peer SIG. After both SIGs the directional ChaCha-Poly1305 keys are available
    /// via <see cref="OutCipherKey"/>/<see cref="InCipherKey"/> for the record layer.
    /// </para>
    /// </summary>
    public sealed class SptpsHandshake
    {
        readonly IDhGroup _dh;
        readonly ISignatureAlgo _sig;
        readonly bool _initiator;
        readonly byte[] _myPrivateKey;   // Ed25519 32-byte seed
        readonly byte[] _peerPublicKey;  // Ed25519 32-byte public
        readonly byte[] _label;

        byte[]? _myEphemeralPrivate;
        SptpsKex? _myKex;
        SptpsKex? _hisKex;
        byte[]? _keyMaterial; // 128 bytes: key0 || key1
        bool _verified;

        /// <summary>
        /// Builds a handshake side.
        /// </summary>
        /// <param name="initiator">True for the connecting (outgoing) peer.</param>
        /// <param name="myEd25519PrivateKey">This node's 32-byte Ed25519 private seed (signs the SIG).</param>
        /// <param name="peerEd25519PublicKey">The expected peer's 32-byte Ed25519 public key (verifies its SIG).</param>
        /// <param name="label">The SPTPS label bytes (e.g. <c>"tinc TCP key expansion &lt;initiator&gt; &lt;responder&gt;\0"</c>).</param>
        public SptpsHandshake(
            bool initiator,
            byte[] myEd25519PrivateKey,
            byte[] peerEd25519PublicKey,
            byte[] label,
            IDhGroup? dhGroup = null,
            ISignatureAlgo? signature = null)
        {
            _sig = signature ?? new Ed25519Signer();
            // SPTPS uses tinc's Ed25519-keyed ECDH (Edwards public on the wire, Montgomery-ladder shared), NOT plain
            // X25519 — see SptpsEcdh. Curve25519DhGroup would derive a different shared secret and break the cipher.
            _dh = dhGroup ?? new SptpsEcdh();
            if (myEd25519PrivateKey is null || myEd25519PrivateKey.Length != _sig.PrivateKeySizeInBytes)
                throw new ArgumentException("Ed25519 private key size mismatch.", nameof(myEd25519PrivateKey));
            if (peerEd25519PublicKey is null || peerEd25519PublicKey.Length != _sig.PublicKeySizeInBytes)
                throw new ArgumentException("Ed25519 public key size mismatch.", nameof(peerEd25519PublicKey));
            _initiator = initiator;
            _myPrivateKey = (byte[])myEd25519PrivateKey.Clone();
            _peerPublicKey = (byte[])peerEd25519PublicKey.Clone();
            _label = (byte[])label.Clone();
        }

        /// <summary>Convenience: builds the meta-connection label <c>"tinc TCP key expansion {init} {resp}\0"</c>.</summary>
        public static byte[] BuildMetaLabel(string initiatorName, string responderName)
        {
            // Matches protocol_auth.c: snprintf(label, 25+strlen(a)+strlen(b), "tinc TCP key expansion %s %s", a, b)
            // and passes that whole length (including the trailing NUL) to sptps_start.
            string text = $"tinc TCP key expansion {initiatorName} {responderName}";
            byte[] body = Encoding.ASCII.GetBytes(text);
            byte[] withNul = new byte[body.Length + 1];
            Array.Copy(body, withNul, body.Length);
            return withNul; // trailing NUL already zero
        }

        /// <summary>Generates this side's ephemeral keypair and returns the KEX message to send (65 bytes).</summary>
        public byte[] CreateKex()
        {
            _myEphemeralPrivate = _dh.GeneratePrivateKey();
            byte[] pub = _dh.DerivePublicValue(_myEphemeralPrivate);
            byte[] nonce = new byte[SptpsConstants.NonceSize];
            using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
                rng.GetBytes(nonce);
            _myKex = new SptpsKex(SptpsConstants.Version, nonce, pub);
            return _myKex.ToBytes();
        }

        /// <summary>
        /// Consumes the peer's KEX (65 bytes), derives the ECDH shared secret and runs the SPTPS PRF to produce the
        /// 128-byte key material. Must be called after <see cref="CreateKex"/>.
        /// </summary>
        public void ConsumeKex(ReadOnlySpan<byte> kexMessage)
        {
            if (_myEphemeralPrivate is null || _myKex is null)
                throw new InvalidOperationException("CreateKex must be called before ConsumeKex.");
            _hisKex = SptpsKex.Parse(kexMessage);

            byte[] shared = _dh.DeriveSharedSecret(_myEphemeralPrivate, _hisKex.PublicKey);
            byte[] seed = BuildKdfSeed();
            _keyMaterial = SptpsPrf.Expand(shared, seed, SptpsConstants.KeyMaterialSize);
        }

        /// <summary>Builds this side's SIG payload: an Ed25519 signature (64 bytes) over the local transcript.</summary>
        public byte[] CreateSig()
        {
            if (_myKex is null || _hisKex is null)
                throw new InvalidOperationException("ConsumeKex must be called before CreateSig.");
            byte[] transcript = BuildSignedTranscript(_initiator, _myKex, _hisKex);
            return _sig.Sign(_myPrivateKey, transcript);
        }

        /// <summary>
        /// Verifies the peer's SIG (64-byte Ed25519 signature) against the reconstructed peer transcript. Returns true
        /// on success; on success the directional keys become available.
        /// </summary>
        public bool ConsumeSig(ReadOnlySpan<byte> signature)
        {
            if (_myKex is null || _hisKex is null)
                throw new InvalidOperationException("ConsumeKex must be called before ConsumeSig.");
            if (signature.Length != SptpsConstants.SignatureSize) return false;
            // Peer signs with its own flag (!ours) and its own kex first: fill_msg(!initiator, hiskex, mykex, label).
            byte[] transcript = BuildSignedTranscript(!_initiator, _hisKex, _myKex);
            _verified = _sig.Verify(_peerPublicKey, transcript, signature);
            return _verified;
        }

        /// <summary>The key (64 bytes) used to seal outgoing records. Initiator → key1; responder → key0.</summary>
        public byte[] OutCipherKey => DirectionalKey(_initiator);

        /// <summary>The key (64 bytes) used to open incoming records. Initiator → key0; responder → key1.</summary>
        public byte[] InCipherKey => DirectionalKey(!_initiator);

        /// <summary>True once the peer SIG has verified.</summary>
        public bool IsVerified => _verified;

        byte[] DirectionalKey(bool useKey1)
        {
            if (_keyMaterial is null)
                throw new InvalidOperationException("Key material not derived yet (call ConsumeKex first).");
            int offset = useKey1 ? SptpsConstants.CipherKeySize : 0;
            byte[] key = new byte[SptpsConstants.CipherKeySize];
            Array.Copy(_keyMaterial, offset, key, 0, SptpsConstants.CipherKeySize);
            return key;
        }

        byte[] BuildKdfSeed()
        {
            // "key expansion"(13, no NUL) || initiator_nonce(32) || responder_nonce(32) || label.
            byte[] prefix = Encoding.ASCII.GetBytes(SptpsConstants.KeyExpansionLabel);
            byte[] initiatorNonce = _initiator ? _myKex!.Nonce : _hisKex!.Nonce;
            byte[] responderNonce = _initiator ? _hisKex!.Nonce : _myKex!.Nonce;

            byte[] seed = new byte[prefix.Length + initiatorNonce.Length + responderNonce.Length + _label.Length];
            int p = 0;
            Buffer.BlockCopy(prefix, 0, seed, p, prefix.Length); p += prefix.Length;
            Buffer.BlockCopy(initiatorNonce, 0, seed, p, initiatorNonce.Length); p += initiatorNonce.Length;
            Buffer.BlockCopy(responderNonce, 0, seed, p, responderNonce.Length); p += responderNonce.Length;
            Buffer.BlockCopy(_label, 0, seed, p, _label.Length);
            return seed;
        }

        byte[] BuildSignedTranscript(bool initiatorFlag, SptpsKex kex0, SptpsKex kex1)
        {
            // fill_msg: initiator_flag(1) || kex0(65) || kex1(65) || label.
            byte[] k0 = kex0.ToBytes();
            byte[] k1 = kex1.ToBytes();
            byte[] msg = new byte[1 + k0.Length + k1.Length + _label.Length];
            int p = 0;
            msg[p++] = (byte)(initiatorFlag ? 1 : 0);
            Buffer.BlockCopy(k0, 0, msg, p, k0.Length); p += k0.Length;
            Buffer.BlockCopy(k1, 0, msg, p, k1.Length); p += k1.Length;
            Buffer.BlockCopy(_label, 0, msg, p, _label.Length);
            return msg;
        }
    }
}
