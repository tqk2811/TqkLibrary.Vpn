namespace TqkLibrary.VpnClient.WireGuard.Handshake.Models
{
    /// <summary>
    /// An X25519 key pair (32-byte private + 32-byte public) — a WireGuard static or ephemeral identity. Generate
    /// one with <see cref="WireGuardHandshake.GenerateKeyPair"/>; build one from a known private key (e.g. a config
    /// <c>PrivateKey =</c> line) with <see cref="WireGuardHandshake.KeyPairFromPrivate"/>.
    /// </summary>
    public sealed record WireGuardKeyPair
    {
        /// <summary>The X25519 private key (32 bytes).</summary>
        public required byte[] PrivateKey { get; init; }

        /// <summary>The X25519 public key (32 bytes) derived from <see cref="PrivateKey"/>.</summary>
        public required byte[] PublicKey { get; init; }
    }
}
