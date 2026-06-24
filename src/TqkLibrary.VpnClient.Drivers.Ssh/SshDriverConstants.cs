namespace TqkLibrary.VpnClient.Drivers.Ssh
{
    /// <summary>Driver-level constants for the SSH driver (defaults not part of the wire protocol).</summary>
    public static class SshDriverConstants
    {
        /// <summary>The driver name tag.</summary>
        public const string DriverName = "ssh";

        /// <summary>The default SSH port.</summary>
        public const int DefaultPort = 22;

        /// <summary>
        /// Default tunnel MTU. A tun@openssh.com layer-3 packet rides one SSH_MSG_CHANNEL_DATA inside a binary packet, so
        /// the headroom below a 1500 path is the SSH packet + cipher + the 8-byte tun framing overhead — 1400 is a safe
        /// conservative default.
        /// </summary>
        public const int DefaultMtu = 1400;
    }
}
