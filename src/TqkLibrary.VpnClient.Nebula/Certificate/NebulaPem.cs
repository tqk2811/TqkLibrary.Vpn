using System.Text;

namespace TqkLibrary.VpnClient.Nebula.Certificate
{
    /// <summary>
    /// Decodes the PEM containers <c>nebula-cert</c> writes (<c>-----BEGIN &lt;banner&gt;-----</c> … base64 …
    /// <c>-----END &lt;banner&gt;-----</c>). Banners include <c>NEBULA CERTIFICATE</c> (a marshaled
    /// <see cref="Models.NebulaCertificate"/>), <c>NEBULA X25519 PRIVATE/PUBLIC KEY</c> (raw 32-byte DH keys) and
    /// <c>NEBULA ED25519 PRIVATE/PUBLIC KEY</c> (raw Ed25519 keys, the private one being seed||public = 64 bytes).
    /// </summary>
    public static class NebulaPem
    {
        /// <summary>Banner of a marshaled Nebula certificate.</summary>
        public const string BannerCertificate = "NEBULA CERTIFICATE";

        /// <summary>Banner of a host's X25519 private key (the Noise static private key).</summary>
        public const string BannerX25519Private = "NEBULA X25519 PRIVATE KEY";

        /// <summary>Banner of a host's X25519 public key.</summary>
        public const string BannerX25519Public = "NEBULA X25519 PUBLIC KEY";

        /// <summary>Banner of an Ed25519 private key (64 bytes: 32-byte seed followed by the 32-byte public key).</summary>
        public const string BannerEd25519Private = "NEBULA ED25519 PRIVATE KEY";

        /// <summary>Banner of an Ed25519 public key.</summary>
        public const string BannerEd25519Public = "NEBULA ED25519 PUBLIC KEY";

        /// <summary>
        /// Decodes the first PEM block in <paramref name="pem"/>, returning its banner and the base64-decoded body.
        /// </summary>
        public static (string Banner, byte[] Body) Decode(string pem)
        {
            if (pem is null) throw new ArgumentNullException(nameof(pem));
            string[] lines = pem.Replace("\r\n", "\n").Split('\n');
            string? banner = null;
            var body = new StringBuilder();
            bool inBlock = false;
            foreach (string raw in lines)
            {
                string line = raw.Trim();
                if (line.StartsWith("-----BEGIN ", StringComparison.Ordinal) && line.EndsWith("-----", StringComparison.Ordinal))
                {
                    banner = line.Substring("-----BEGIN ".Length, line.Length - "-----BEGIN ".Length - "-----".Length);
                    inBlock = true;
                    continue;
                }
                if (line.StartsWith("-----END ", StringComparison.Ordinal))
                    break;
                if (inBlock && line.Length != 0)
                    body.Append(line);
            }
            if (banner is null) throw new FormatException("No PEM block found.");
            return (banner, Convert.FromBase64String(body.ToString()));
        }

        /// <summary>
        /// Decodes an Ed25519 private-key PEM body and returns just the 32-byte seed (Nebula stores the Go-format
        /// 64-byte private key = seed || public; only the seed is needed to sign).
        /// </summary>
        public static byte[] DecodeEd25519Seed(string pem)
        {
            (string banner, byte[] body) = Decode(pem);
            if (banner != BannerEd25519Private)
                throw new FormatException($"Expected '{BannerEd25519Private}', got '{banner}'.");
            // Go's ed25519.PrivateKey is 64 bytes (seed||pub); older/raw forms may be the 32-byte seed alone.
            return body.Length == 64 ? body.AsSpan(0, 32).ToArray() : body;
        }
    }
}
