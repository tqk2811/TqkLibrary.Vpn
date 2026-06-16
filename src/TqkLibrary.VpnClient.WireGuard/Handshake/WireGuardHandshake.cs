using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Crypto.Aead;
using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.WireGuard.Handshake.Models;

namespace TqkLibrary.VpnClient.WireGuard.Handshake
{
    /// <summary>
    /// Drives one side of the WireGuard <c>Noise_IKpsk2_25519_ChaCha20Poly1305_BLAKE2s</c> handshake (whitepaper
    /// §5.4) for a single session: the initiator path
    /// (<see cref="CreateInitiation"/> → <see cref="ConsumeResponse"/>) or the responder path
    /// (<see cref="ConsumeInitiation"/> → <see cref="CreateResponse"/>), finishing with <see cref="DeriveTransportKeys"/>.
    /// <para>
    /// All symmetric work is delegated to <see cref="NoiseSymmetricState"/> (V3.a) and all Diffie-Hellman to
    /// <see cref="Curve25519DhGroup"/>; this class only sequences the mixes, DHs and AEADs exactly as the whitepaper
    /// prescribes and hands the encrypted fields to <see cref="WireGuardMessageCodec"/>. It is pure protocol logic —
    /// no sockets, no timers, no mac1/mac2 (those are the V3.c layer). Each <c>KDF1(ck, x)</c> in the whitepaper is
    /// realised as <see cref="NoiseSymmetricState.MixKey"/> (KDF2): the first KDF output — the new chaining key — is
    /// identical, and the extra cipher key it installs is always overwritten before the next AEAD, so the transcript
    /// is unaffected. The preshared-key step <c>KDF3</c> is <see cref="NoiseSymmetricState.MixKeyAndHash"/>.
    /// </para>
    /// </summary>
    public sealed class WireGuardHandshake
    {
        readonly NoiseSymmetricState _state;
        readonly IDhGroup _dh;
        readonly WireGuardTai64n _timestamps;
        readonly WireGuardKeyPair _localStatic;
        readonly byte[] _presharedKey;            // 32 bytes; all-zero when no PSK is configured
        readonly byte[]? _remoteStaticPublic;     // peer's static public key — required for the initiator

        WireGuardKeyPair? _localEphemeral;         // generated when this side sends its ephemeral
        byte[]? _remoteEphemeralPublic;            // learned from the peer's message
        byte[]? _remoteStaticPublicLearned;        // responder: initiator's static public, recovered from the initiation
        bool _isInitiator;

        /// <summary>
        /// Builds a handshake bound to this peer's <paramref name="localStatic"/> identity. Pass
        /// <paramref name="remoteStaticPublic"/> (the peer's static public key) for the <b>initiator</b> — it is the
        /// <c>Sresp^pub</c> mixed before the first message; the responder learns the initiator's static key from the
        /// initiation message and may pass <c>null</c>. <paramref name="presharedKey"/> is the optional 32-byte
        /// WireGuard PSK (<c>null</c> ⇒ all-zero, i.e. PSK disabled). Optional primitives default to the F.4 set
        /// (HMAC-BLAKE2s / BLAKE2s / ChaCha20-Poly1305 and X25519).
        /// </summary>
        public WireGuardHandshake(
            WireGuardKeyPair localStatic,
            byte[]? remoteStaticPublic = null,
            byte[]? presharedKey = null,
            IPrf? prf = null,
            IHashAlgo? hash = null,
            IAeadCipher? cipher = null,
            IDhGroup? dhGroup = null,
            WireGuardTai64n? timestamps = null)
        {
            _localStatic = localStatic ?? throw new ArgumentNullException(nameof(localStatic));
            if (localStatic.PrivateKey is null || localStatic.PrivateKey.Length != WireGuardConstants.KeyLength)
                throw new ArgumentException("Static private key must be 32 bytes.", nameof(localStatic));
            if (remoteStaticPublic is not null && remoteStaticPublic.Length != WireGuardConstants.KeyLength)
                throw new ArgumentException("Remote static public key must be 32 bytes.", nameof(remoteStaticPublic));
            if (presharedKey is not null && presharedKey.Length != WireGuardConstants.KeyLength)
                throw new ArgumentException("Preshared key must be 32 bytes.", nameof(presharedKey));

            _dh = dhGroup ?? new Curve25519DhGroup();
            _state = new NoiseSymmetricState(prf ?? new HmacBlake2sPrf(), hash ?? new Blake2s(), cipher ?? new ChaCha20Poly1305Cipher());
            _timestamps = timestamps ?? new WireGuardTai64n();
            _remoteStaticPublic = remoteStaticPublic;
            _presharedKey = presharedKey ?? new byte[WireGuardConstants.KeyLength];
        }

        /// <summary>The X25519 group this handshake uses, exposed so callers can generate/derive matching keys.</summary>
        public IDhGroup DhGroup => _dh;

        /// <summary>Generates a fresh X25519 key pair (used for static identities or, internally, for ephemerals).</summary>
        public WireGuardKeyPair GenerateKeyPair()
        {
            byte[] priv = _dh.GeneratePrivateKey();
            return new WireGuardKeyPair { PrivateKey = priv, PublicKey = _dh.DerivePublicValue(priv) };
        }

        /// <summary>Builds a key pair from a known 32-byte X25519 private key, deriving the matching public key.</summary>
        public WireGuardKeyPair KeyPairFromPrivate(byte[] privateKey)
        {
            if (privateKey is null || privateKey.Length != WireGuardConstants.KeyLength)
                throw new ArgumentException("Private key must be 32 bytes.", nameof(privateKey));
            return new WireGuardKeyPair { PrivateKey = (byte[])privateKey.Clone(), PublicKey = _dh.DerivePublicValue(privateKey) };
        }

        /// <summary>
        /// <b>Initiator</b> step 1 — builds the type-1 initiation message for session <paramref name="senderIndex"/>
        /// (whitepaper §5.4.2). Generates the ephemeral, runs the two static DHs, and seals the static key and the
        /// TAI64N timestamp. mac1/mac2 are left zero (V3.c). Requires the remote static public key from the ctor.
        /// </summary>
        public WireGuardInitiationMessage CreateInitiation(uint senderIndex)
        {
            if (_remoteStaticPublic is null)
                throw new InvalidOperationException("The initiator needs the peer's static public key (pass it to the constructor).");
            _isInitiator = true;

            // Ci = HASH(CONSTRUCTION); Hi = HASH(Ci || IDENTIFIER); Hi = HASH(Hi || Sresp^pub)
            _state.InitializeWireGuard();
            _state.MixHash(_remoteStaticPublic);

            // (Ei^priv, Ei^pub) = DH-GENERATE(); Ci = KDF1(Ci, Ei^pub); msg.ephemeral = Ei^pub; Hi = HASH(Hi || msg.ephemeral)
            _localEphemeral = GenerateKeyPair();
            _state.MixKey(_localEphemeral.PublicKey);
            _state.MixHash(_localEphemeral.PublicKey);

            // (Ci, k) = KDF2(Ci, DH(Ei^priv, Sresp^pub)); msg.static = AEAD(k, 0, Sinit^pub, Hi)
            _state.MixKey(_dh.DeriveSharedSecret(_localEphemeral.PrivateKey, _remoteStaticPublic));
            byte[] encryptedStatic = _state.EncryptAndHash(_localStatic.PublicKey);

            // (Ci, k) = KDF2(Ci, DH(Sinit^priv, Sresp^pub)); msg.timestamp = AEAD(k, 0, TIMESTAMP(), Hi)
            _state.MixKey(_dh.DeriveSharedSecret(_localStatic.PrivateKey, _remoteStaticPublic));
            byte[] encryptedTimestamp = _state.EncryptAndHash(_timestamps.Now());

            return new WireGuardInitiationMessage
            {
                SenderIndex = senderIndex,
                UnencryptedEphemeral = _localEphemeral.PublicKey,
                EncryptedStatic = encryptedStatic,
                EncryptedTimestamp = encryptedTimestamp,
            };
        }

        /// <summary>
        /// <b>Responder</b> step 1 — consumes a type-1 initiation message, recovering the initiator's static public
        /// key and TAI64N timestamp (whitepaper §5.4.2). Returns <c>false</c> if either AEAD fails to authenticate
        /// (the message is forged or for a different responder), leaving no usable state.
        /// </summary>
        public bool ConsumeInitiation(WireGuardInitiationMessage message, out byte[] initiatorStaticPublic, out byte[] timestamp)
        {
            if (message is null) throw new ArgumentNullException(nameof(message));
            initiatorStaticPublic = Array.Empty<byte>();
            timestamp = Array.Empty<byte>();
            _isInitiator = false;

            // Ci = HASH(CONSTRUCTION); Hi = HASH(Ci || IDENTIFIER); Hi = HASH(Hi || Sresp^pub) — our own static public
            _state.InitializeWireGuard();
            _state.MixHash(_localStatic.PublicKey);

            // Ci = KDF1(Ci, msg.ephemeral); Hi = HASH(Hi || msg.ephemeral)
            _remoteEphemeralPublic = (byte[])message.UnencryptedEphemeral.Clone();
            _state.MixKey(_remoteEphemeralPublic);
            _state.MixHash(_remoteEphemeralPublic);

            // (Ci, k) = KDF2(Ci, DH(Sresp^priv, Ei^pub)); Sinit^pub = AEAD-OPEN(k, 0, msg.static, Hi)
            _state.MixKey(_dh.DeriveSharedSecret(_localStatic.PrivateKey, _remoteEphemeralPublic));
            byte[]? openedStatic = _state.DecryptAndHash(message.EncryptedStatic);
            if (openedStatic is null) return false;

            // (Ci, k) = KDF2(Ci, DH(Sresp^priv, Sinit^pub)); TIMESTAMP() = AEAD-OPEN(k, 0, msg.timestamp, Hi)
            _state.MixKey(_dh.DeriveSharedSecret(_localStatic.PrivateKey, openedStatic));
            byte[]? openedTimestamp = _state.DecryptAndHash(message.EncryptedTimestamp);
            if (openedTimestamp is null) return false;

            _remoteStaticPublicLearned = openedStatic;
            initiatorStaticPublic = openedStatic;
            timestamp = openedTimestamp;
            return true;
        }

        /// <summary>
        /// <b>Responder</b> step 2 — builds the type-2 response message for session <paramref name="senderIndex"/>,
        /// echoing <paramref name="receiverIndex"/> (the initiator's index) (whitepaper §5.4.3). Generates the
        /// responder ephemeral, runs both ephemeral DHs, mixes the preshared key, and seals the empty payload. Must
        /// be called after a successful <see cref="ConsumeInitiation"/>.
        /// </summary>
        public WireGuardResponseMessage CreateResponse(uint senderIndex, uint receiverIndex)
        {
            if (_isInitiator || _remoteEphemeralPublic is null || _remoteStaticPublicLearned is null)
                throw new InvalidOperationException("CreateResponse requires a successful ConsumeInitiation first.");

            // (Er^priv, Er^pub) = DH-GENERATE(); Cr = KDF1(Cr, Er^pub); msg.ephemeral = Er^pub; Hr = HASH(Hr || msg.ephemeral)
            _localEphemeral = GenerateKeyPair();
            _state.MixKey(_localEphemeral.PublicKey);
            _state.MixHash(_localEphemeral.PublicKey);

            // Cr = KDF1(Cr, DH(Er^priv, Ei^pub))
            _state.MixKey(_dh.DeriveSharedSecret(_localEphemeral.PrivateKey, _remoteEphemeralPublic));
            // Cr = KDF1(Cr, DH(Er^priv, Si^pub))
            _state.MixKey(_dh.DeriveSharedSecret(_localEphemeral.PrivateKey, _remoteStaticPublicLearned));
            // (Cr, τ, k) = KDF3(Cr, Q); Hr = HASH(Hr || τ)
            _state.MixKeyAndHash(_presharedKey);
            // msg.empty = AEAD(k, 0, ε, Hr)
            byte[] encryptedNothing = _state.EncryptAndHash(ReadOnlySpan<byte>.Empty);

            return new WireGuardResponseMessage
            {
                SenderIndex = senderIndex,
                ReceiverIndex = receiverIndex,
                UnencryptedEphemeral = _localEphemeral.PublicKey,
                EncryptedNothing = encryptedNothing,
            };
        }

        /// <summary>
        /// <b>Initiator</b> step 2 — consumes the type-2 response message, completing the handshake (whitepaper
        /// §5.4.3). Runs the two ephemeral DHs, mixes the preshared key and authenticates the empty payload. Returns
        /// <c>false</c> if the AEAD fails (forged response or PSK mismatch). Must follow <see cref="CreateInitiation"/>.
        /// </summary>
        public bool ConsumeResponse(WireGuardResponseMessage message)
        {
            if (message is null) throw new ArgumentNullException(nameof(message));
            if (!_isInitiator || _localEphemeral is null || _remoteStaticPublic is null)
                throw new InvalidOperationException("ConsumeResponse requires a CreateInitiation first.");

            // Cr = KDF1(Cr, msg.ephemeral); Hr = HASH(Hr || msg.ephemeral)
            _remoteEphemeralPublic = (byte[])message.UnencryptedEphemeral.Clone();
            _state.MixKey(_remoteEphemeralPublic);
            _state.MixHash(_remoteEphemeralPublic);

            // Cr = KDF1(Cr, DH(Ei^priv, Er^pub))
            _state.MixKey(_dh.DeriveSharedSecret(_localEphemeral.PrivateKey, _remoteEphemeralPublic));
            // Cr = KDF1(Cr, DH(Si^priv, Er^pub))
            _state.MixKey(_dh.DeriveSharedSecret(_localStatic.PrivateKey, _remoteEphemeralPublic));
            // (Cr, τ, k) = KDF3(Cr, Q); Hr = HASH(Hr || τ)
            _state.MixKeyAndHash(_presharedKey);
            // ε = AEAD-OPEN(k, 0, msg.empty, Hr)
            byte[]? opened = _state.DecryptAndHash(message.EncryptedNothing);
            return opened is not null;
        }

        /// <summary>
        /// Noise <c>Split</c> at the end of the handshake (whitepaper §5.4.4): derives the transport key pair from
        /// the final chaining key and orients it for this peer's role. The first KDF output is the initiator's send
        /// key and the second the responder's send key, so the responder swaps the pair — the result is that this
        /// side's <see cref="WireGuardTransportKeys.SendKey"/> equals the peer's <see cref="WireGuardTransportKeys.ReceiveKey"/>.
        /// </summary>
        public WireGuardTransportKeys DeriveTransportKeys()
        {
            (byte[] first, byte[] second) = _state.Split();
            return _isInitiator
                ? new WireGuardTransportKeys { SendKey = first, ReceiveKey = second }
                : new WireGuardTransportKeys { SendKey = second, ReceiveKey = first };
        }
    }
}
