namespace TqkLibrary.VpnClient.OpenVpn.Enums
{
    /// <summary>
    /// Selects which halves of a 2048-bit OpenVPN static key (the <c>key2</c> structure: two {cipher, hmac} key sets)
    /// a peer uses for its outgoing vs incoming direction. <c>--key-direction</c> in a profile: omitted ⇒
    /// <see cref="Bidirectional"/> (both ends use set 0 for both directions); <c>0</c> ⇒ <see cref="Normal"/> (the
    /// server's value); <c>1</c> ⇒ <see cref="Inverse"/> (the client's value). The two ends must be complementary so
    /// one's out-key equals the other's in-key. tls-crypt has no such option — its direction is fixed by role.
    /// </summary>
    public enum OpenVpnKeyDirection
    {
        /// <summary>No <c>key-direction</c>: both directions use key set 0 (out = 0, in = 0).</summary>
        Bidirectional = 0,

        /// <summary><c>key-direction 0</c> (the server side): out = key set 0, in = key set 1.</summary>
        Normal = 1,

        /// <summary><c>key-direction 1</c> (the client side): out = key set 1, in = key set 0.</summary>
        Inverse = 2,
    }
}
