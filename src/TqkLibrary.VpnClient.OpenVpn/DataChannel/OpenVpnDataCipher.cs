using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;
using TqkLibrary.VpnClient.Crypto.Aead;

namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// A data-channel AEAD cipher the client can negotiate via NCP (V2.f). It bundles the OpenVPN cipher name (as it
    /// appears in <c>IV_CIPHERS</c> and the pushed <c>cipher</c> option), the key length to slice from the derived
    /// key2, and a factory for the matching <see cref="IAeadCipher"/>. The client advertises <see cref="Supported"/>
    /// in its peer-info; the server picks one and echoes it in PUSH_REPLY, which <see cref="TryResolve"/> maps back.
    /// </summary>
    public sealed class OpenVpnDataCipher
    {
        readonly Func<IAeadCipher> _factory;

        OpenVpnDataCipher(string name, int keySizeBytes, Func<IAeadCipher> factory)
        {
            Name = name;
            KeySizeBytes = keySizeBytes;
            _factory = factory;
        }

        /// <summary>The OpenVPN cipher name (e.g. <c>AES-256-GCM</c>).</summary>
        public string Name { get; }

        /// <summary>The cipher key length in bytes sliced from key2 (16 = AES-128, 32 = AES-256).</summary>
        public int KeySizeBytes { get; }

        /// <summary>Creates a fresh AEAD cipher instance for this algorithm.</summary>
        public IAeadCipher CreateCipher() => _factory();

        /// <summary>AES-256-GCM (the default and OpenVPN's preferred data cipher).</summary>
        public static OpenVpnDataCipher Aes256Gcm { get; } = new("AES-256-GCM", 32, () => new AesGcmCipher(32));

        /// <summary>AES-128-GCM.</summary>
        public static OpenVpnDataCipher Aes128Gcm { get; } = new("AES-128-GCM", 16, () => new AesGcmCipher(16));

        /// <summary>The ciphers this client advertises, in preference order. (CHACHA20-POLY1305 awaits F.4's AEAD.)</summary>
        public static IReadOnlyList<OpenVpnDataCipher> Supported { get; } = new[] { Aes256Gcm, Aes128Gcm };

        /// <summary>The colon-separated <c>IV_CIPHERS</c> list advertised in peer-info (e.g. <c>AES-256-GCM:AES-128-GCM</c>).</summary>
        public static string AdvertisedList => string.Join(":", Supported.Select(c => c.Name));

        /// <summary>Resolves a negotiated cipher name (case-insensitive) to a supported descriptor.</summary>
        public static bool TryResolve(string? name, out OpenVpnDataCipher cipher)
        {
            foreach (OpenVpnDataCipher candidate in Supported)
                if (string.Equals(candidate.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    cipher = candidate;
                    return true;
                }
            cipher = Aes256Gcm;
            return false;
        }
    }
}
