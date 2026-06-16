namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// OpenVPN keepalive ("ping") payload — a fixed 16-byte magic carried as an ordinary data-channel packet
    /// (encrypted like any payload). A decrypted data packet whose plaintext equals this magic is a keepalive and must
    /// not be forwarded to the IP stack. See <see cref="OpenVpnKeepalive"/> for the send/timeout timing.
    /// </summary>
    public static class OpenVpnPing
    {
        static readonly byte[] _magic =
        {
            0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
            0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
        };

        /// <summary>The 16-byte ping magic (OpenVPN's <c>ping_string</c>).</summary>
        public static ReadOnlySpan<byte> Magic => _magic;

        /// <summary>True if a decrypted data payload is the keepalive ping (and so should be dropped, not forwarded).</summary>
        public static bool IsPing(ReadOnlySpan<byte> plaintext) => plaintext.SequenceEqual(_magic);
    }
}
