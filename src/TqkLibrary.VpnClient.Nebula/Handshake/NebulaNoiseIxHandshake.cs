using System.Text;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Crypto.Aead;
using TqkLibrary.VpnClient.Crypto.Noise;

namespace TqkLibrary.VpnClient.Nebula.Handshake
{
    /// <summary>
    /// Drives one side of the Nebula <c>Noise_IX_25519_AESGCM_SHA256</c> handshake for a single session, reusing the
    /// generic <see cref="NoiseSymmetricState"/> (V3.a, unchanged) for all symmetric work and
    /// <see cref="Curve25519DhGroup"/> for the DHs. This class only sequences the IX tokens per the Noise spec
    /// (§5.3/§7.5) and seals/opens the per-message payloads.
    /// <para>
    /// Pattern IX — pre-messages empty; <c>msg1: e, s</c> (initiator→responder, both plaintext+MixHash since no key
    /// is set yet); <c>msg2: e, ee, se, s, es</c> (responder→initiator, <c>s</c> and the payload AEAD-encrypted after
    /// the DHs). DH token convention: the first letter is the initiator's key, the second the responder's. Prologue
    /// is empty and there is no PSK, so the protocol name is exactly <see cref="ProtocolName"/>.
    /// </para>
    /// </summary>
    public sealed class NebulaNoiseIxHandshake
    {
        /// <summary>The Noise protocol name Nebula seeds the SymmetricState with (default AES-256-GCM cipher).</summary>
        public const string ProtocolName = "Noise_IX_25519_AESGCM_SHA256";

        const int KeySize = 32;

        readonly NoiseSymmetricState _state;
        readonly IDhGroup _dh;
        readonly byte[] _localStaticPrivate;
        readonly byte[] _localStaticPublic;
        readonly string _name;

        byte[]? _localEphemeralPrivate;
        byte[]? _remoteEphemeralPublic;
        byte[]? _remoteStaticPublic;
        bool _isInitiator;

        /// <summary>
        /// Builds a handshake bound to this peer's static X25519 key pair. For the Nebula default the symmetric
        /// primitives are HMAC-SHA256 / SHA-256 / AES-256-GCM; pass <paramref name="cipher"/> =
        /// <see cref="ChaCha20Poly1305Cipher"/> for a <c>chachapoly</c> network. The protocol name is fixed to
        /// AES-GCM's spelling regardless — only the cipher implementation changes — matching Nebula, which keeps the
        /// AESGCM name unless explicitly configured for ChaCha (then the name's cipher segment also changes; pass
        /// <paramref name="protocolName"/> to override for that case).
        /// </summary>
        public NebulaNoiseIxHandshake(
            byte[] localStaticPrivate,
            IDhGroup? dhGroup = null,
            IPrf? prf = null,
            IHashAlgo? hash = null,
            IAeadCipher? cipher = null,
            string? protocolName = null)
        {
            if (localStaticPrivate is null || localStaticPrivate.Length != KeySize)
                throw new ArgumentException("Static private key must be 32 bytes.", nameof(localStaticPrivate));

            _dh = dhGroup ?? new Curve25519DhGroup();
            _state = new NoiseSymmetricState(prf ?? HmacPrf.Sha256(), hash ?? new Sha256Hash(), cipher ?? new AesGcmCipher(32));
            _localStaticPrivate = (byte[])localStaticPrivate.Clone();
            _localStaticPublic = _dh.DerivePublicValue(localStaticPrivate);
            _name = protocolName ?? ProtocolName;
        }

        /// <summary>This side's static public key (32-byte X25519).</summary>
        public byte[] LocalStaticPublic => (byte[])_localStaticPublic.Clone();

        /// <summary>The peer's static public key once learned from the handshake, else <c>null</c>. Copy.</summary>
        public byte[]? RemoteStaticPublic => _remoteStaticPublic is null ? null : (byte[])_remoteStaticPublic.Clone();

        void Initialize()
        {
            _state.InitializeSymmetric(Encoding.ASCII.GetBytes(_name));
            _state.MixHash(ReadOnlySpan<byte>.Empty); // MixHash(prologue); Nebula's prologue is empty
        }

        /// <summary>
        /// <b>Initiator</b> message 1 (<c>e, s</c>): generates the ephemeral, appends it and the (plaintext) static
        /// public key, then the (plaintext) <paramref name="payload"/>. Returns the bytes to place after the Nebula
        /// header: <c>e.pub || s.pub || payload</c> (all in the clear, only folded into the transcript hash).
        /// </summary>
        public byte[] CreateInitiation(ReadOnlySpan<byte> payload)
        {
            _isInitiator = true;
            Initialize();

            _localEphemeralPrivate = _dh.GeneratePrivateKey();
            byte[] ePub = _dh.DerivePublicValue(_localEphemeralPrivate);
            _state.MixHash(ePub);                                    // token e

            byte[] sealedStatic = _state.EncryptAndHash(_localStaticPublic); // token s (no key → plaintext)
            byte[] sealedPayload = _state.EncryptAndHash(payload);           // payload (no key → plaintext)

            return Concat(ePub, sealedStatic, sealedPayload);
        }

        /// <summary>
        /// <b>Responder</b> consumes message 1, learning the initiator's ephemeral + static public keys and the
        /// payload. Returns false if the message is malformed (in IX msg1 nothing is authenticated yet, so this only
        /// fails on length errors).
        /// </summary>
        public bool ConsumeInitiation(ReadOnlySpan<byte> message, out byte[] payload)
        {
            payload = Array.Empty<byte>();
            _isInitiator = false;
            Initialize();

            if (message.Length < KeySize * 2) return false;

            _remoteEphemeralPublic = message.Slice(0, KeySize).ToArray();
            _state.MixHash(_remoteEphemeralPublic);                                  // token e

            byte[]? openedStatic = _state.DecryptAndHash(message.Slice(KeySize, KeySize)); // token s (no key → plaintext)
            if (openedStatic is null) return false;
            _remoteStaticPublic = openedStatic;

            byte[]? openedPayload = _state.DecryptAndHash(message.Slice(KeySize * 2));     // payload (no key → plaintext)
            if (openedPayload is null) return false;

            payload = openedPayload;
            return true;
        }

        /// <summary>
        /// <b>Responder</b> message 2 (<c>e, ee, se, s, es</c>): generates the ephemeral, runs the three DHs, then
        /// seals the static key and <paramref name="payload"/> under the now-established key. Returns
        /// <c>e.pub || enc(s.pub)||tag || enc(payload)||tag</c>. Must follow a successful
        /// <see cref="ConsumeInitiation"/>.
        /// </summary>
        public byte[] CreateResponse(ReadOnlySpan<byte> payload)
        {
            if (_isInitiator || _remoteEphemeralPublic is null || _remoteStaticPublic is null)
                throw new InvalidOperationException("CreateResponse requires a successful ConsumeInitiation first.");

            _localEphemeralPrivate = _dh.GeneratePrivateKey();
            byte[] ePub = _dh.DerivePublicValue(_localEphemeralPrivate);
            _state.MixHash(ePub);                                                                  // token e
            _state.MixKey(_dh.DeriveSharedSecret(_localEphemeralPrivate, _remoteEphemeralPublic)); // ee: DH(e_r, e_i)
            _state.MixKey(_dh.DeriveSharedSecret(_localEphemeralPrivate, _remoteStaticPublic));    // se (responder): DH(e_r, s_i)
            byte[] sealedStatic = _state.EncryptAndHash(_localStaticPublic);                       // token s (AEAD)
            _state.MixKey(_dh.DeriveSharedSecret(_localStaticPrivate, _remoteEphemeralPublic));    // es (responder): DH(s_r, e_i)
            byte[] sealedPayload = _state.EncryptAndHash(payload);                                 // payload (AEAD)

            return Concat(ePub, sealedStatic, sealedPayload);
        }

        /// <summary>
        /// <b>Initiator</b> consumes message 2, completing the handshake: reads the responder ephemeral, runs the
        /// matching DHs, opens the responder static and the payload. Returns false if any AEAD fails (forged or
        /// mismatched peer). Must follow <see cref="CreateInitiation"/>.
        /// </summary>
        public bool ConsumeResponse(ReadOnlySpan<byte> message, out byte[] payload)
        {
            payload = Array.Empty<byte>();
            if (!_isInitiator || _localEphemeralPrivate is null)
                throw new InvalidOperationException("ConsumeResponse requires a CreateInitiation first.");
            if (message.Length < KeySize) return false;

            _remoteEphemeralPublic = message.Slice(0, KeySize).ToArray();
            _state.MixHash(_remoteEphemeralPublic);                                                // token e
            _state.MixKey(_dh.DeriveSharedSecret(_localEphemeralPrivate, _remoteEphemeralPublic)); // ee: DH(e_i, e_r)
            _state.MixKey(_dh.DeriveSharedSecret(_localStaticPrivate, _remoteEphemeralPublic));    // se (initiator): DH(s_i, e_r)

            // token s — AEAD-encrypted 32-byte static + 16-byte tag.
            int rest = message.Length - KeySize;
            if (rest < KeySize + 16) return false;
            byte[]? openedStatic = _state.DecryptAndHash(message.Slice(KeySize, KeySize + 16));
            if (openedStatic is null) return false;
            _remoteStaticPublic = openedStatic;

            _state.MixKey(_dh.DeriveSharedSecret(_localEphemeralPrivate, _remoteStaticPublic));    // es (initiator): DH(e_i, s_r)

            byte[]? openedPayload = _state.DecryptAndHash(message.Slice(KeySize + KeySize + 16));  // payload (AEAD)
            if (openedPayload is null) return false;

            payload = openedPayload;
            return true;
        }

        /// <summary>
        /// Noise <c>Split</c>: derives the transport key pair and orients it for this peer's role. The first KDF
        /// output is the initiator's send key; the responder swaps the pair, so this side's <c>SendKey</c> equals the
        /// peer's <c>ReceiveKey</c>.
        /// </summary>
        public (byte[] SendKey, byte[] ReceiveKey) Split()
        {
            (byte[] first, byte[] second) = _state.Split();
            return _isInitiator ? (first, second) : (second, first);
        }

        static byte[] Concat(byte[] a, byte[] b, byte[] c)
        {
            byte[] result = new byte[a.Length + b.Length + c.Length];
            Buffer.BlockCopy(a, 0, result, 0, a.Length);
            Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
            Buffer.BlockCopy(c, 0, result, a.Length + b.Length, c.Length);
            return result;
        }
    }
}
