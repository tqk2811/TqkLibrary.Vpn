namespace TqkLibrary.VpnClient.Tinc.Sptps.Models
{
    /// <summary>
    /// The SPTPS KEX (key-exchange) message, <c>sptps_kex_t</c> — a fixed 65-byte structure exchanged in the clear at
    /// the start of a handshake: <c>version(1) || nonce(32) || pubkey(32)</c>. The version is
    /// <see cref="SptpsConstants.Version"/> (0); the nonce is random; the pubkey is the ephemeral X25519 public value.
    /// </summary>
    public sealed class SptpsKex
    {
        /// <summary>Wire size of a KEX message (<c>sizeof(sptps_kex_t)</c>).</summary>
        public const int Size = 1 + SptpsConstants.NonceSize + SptpsConstants.EcdhSize;

        /// <summary>The KEX version byte (always <see cref="SptpsConstants.Version"/>).</summary>
        public byte Version { get; }

        /// <summary>The 32-byte random nonce mixed into the key-derivation seed and signed in the SIG transcript.</summary>
        public byte[] Nonce { get; }

        /// <summary>The 32-byte ephemeral X25519 public value.</summary>
        public byte[] PublicKey { get; }

        public SptpsKex(byte version, byte[] nonce, byte[] publicKey)
        {
            if (nonce is null || nonce.Length != SptpsConstants.NonceSize)
                throw new ArgumentException($"Nonce must be {SptpsConstants.NonceSize} bytes.", nameof(nonce));
            if (publicKey is null || publicKey.Length != SptpsConstants.EcdhSize)
                throw new ArgumentException($"Public key must be {SptpsConstants.EcdhSize} bytes.", nameof(publicKey));
            Version = version;
            Nonce = nonce;
            PublicKey = publicKey;
        }

        /// <summary>Serialises this KEX into its fixed 65-byte wire form.</summary>
        public byte[] ToBytes()
        {
            byte[] buffer = new byte[Size];
            buffer[0] = Version;
            Buffer.BlockCopy(Nonce, 0, buffer, 1, SptpsConstants.NonceSize);
            Buffer.BlockCopy(PublicKey, 0, buffer, 1 + SptpsConstants.NonceSize, SptpsConstants.EcdhSize);
            return buffer;
        }

        /// <summary>Parses a 65-byte KEX message. Throws on a wrong length.</summary>
        public static SptpsKex Parse(ReadOnlySpan<byte> data)
        {
            if (data.Length != Size)
                throw new ArgumentException($"KEX message must be {Size} bytes.", nameof(data));
            byte version = data[0];
            byte[] nonce = data.Slice(1, SptpsConstants.NonceSize).ToArray();
            byte[] pubkey = data.Slice(1 + SptpsConstants.NonceSize, SptpsConstants.EcdhSize).ToArray();
            return new SptpsKex(version, nonce, pubkey);
        }
    }
}
