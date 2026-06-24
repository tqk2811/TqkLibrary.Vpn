using System.Text;

namespace TqkLibrary.VpnClient.Tinc.Hosts
{
    /// <summary>
    /// A parsed tinc host-config file (<c>hosts/&lt;name&gt;</c>): the peer's name, its base64 Ed25519 public key
    /// (<c>Ed25519PublicKey</c>, 32 bytes), the reachable <c>Address</c>(es) / <c>Port</c>, and the <c>Subnet</c>(s)
    /// it routes. Only the fields needed for the SPTPS handshake and routing are surfaced; unknown keys are ignored.
    /// Lines are <c>Key = Value</c>; the RSA PEM block (legacy 1.0 auth) is skipped.
    /// </summary>
    public sealed class TincHostConfig
    {
        /// <summary>The peer node name (from the file name; not stored in the file itself except as <c>Name</c>).</summary>
        public string? Name { get; set; }

        /// <summary>The 32-byte Ed25519 public key, or null if absent.</summary>
        public byte[]? Ed25519PublicKey { get; set; }

        /// <summary>Reachable addresses (hostnames or IPs) in declaration order.</summary>
        public List<string> Addresses { get; } = new List<string>();

        /// <summary>The listening UDP/TCP port (defaults to 655 if unspecified).</summary>
        public int Port { get; set; } = 655;

        /// <summary>Routed subnets (CIDR strings) in declaration order.</summary>
        public List<string> Subnets { get; } = new List<string>();

        /// <summary>Parses host-config text. <paramref name="name"/> seeds <see cref="Name"/> if no Name line is present.</summary>
        public static TincHostConfig Parse(string text, string? name = null)
        {
            var config = new TincHostConfig { Name = name };
            bool inPem = false;
            foreach (string rawLine in text.Split('\n'))
            {
                string line = rawLine.TrimEnd('\r').Trim();
                if (line.Length == 0) continue;

                // Skip the RSA PEM block (legacy 1.0 key) entirely.
                if (line.StartsWith("-----BEGIN", StringComparison.Ordinal)) { inPem = true; continue; }
                if (line.StartsWith("-----END", StringComparison.Ordinal)) { inPem = false; continue; }
                if (inPem) continue;

                int eq = line.IndexOf('=');
                if (eq < 0) continue;
                string key = line.Substring(0, eq).Trim();
                string value = line.Substring(eq + 1).Trim();

                switch (key.ToLowerInvariant())
                {
                    case "name":
                        config.Name = value;
                        break;
                    case "ed25519publickey":
                        config.Ed25519PublicKey = DecodeBase64Key(value);
                        break;
                    case "address":
                        config.Addresses.Add(value);
                        break;
                    case "port":
                        if (int.TryParse(value, out int port)) config.Port = port;
                        break;
                    case "subnet":
                        config.Subnets.Add(value);
                        break;
                }
            }
            return config;
        }

        /// <summary>
        /// Decodes a tinc base64 key using tinc's own (little-endian) Base64 codec — <b>not</b> RFC 4648. tinc keys are
        /// written by <c>ecdsa_get_base64_public_key</c> with <see cref="TincBase64"/>, which packs each quad
        /// little-endian; decoding them with the BCL codec yields a different key. See <see cref="TincBase64"/>.
        /// </summary>
        public static byte[] DecodeBase64Key(string value) => TincBase64.Decode(value.Trim());

        /// <summary>Encodes a key as tinc-style unpadded (little-endian) base64. See <see cref="TincBase64"/>.</summary>
        public static string EncodeBase64Key(ReadOnlySpan<byte> key) => TincBase64.Encode(key);
    }
}
