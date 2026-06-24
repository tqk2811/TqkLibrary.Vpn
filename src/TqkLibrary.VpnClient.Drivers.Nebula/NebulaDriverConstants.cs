namespace TqkLibrary.VpnClient.Drivers.Nebula
{
    /// <summary>Shared constants for the Nebula driver's data plane and timers.</summary>
    public static class NebulaDriverConstants
    {
        /// <summary>The Nebula default tunnel MTU (nebula's <c>tun.mtu</c> default is 1300).</summary>
        public const int DefaultMtu = 1300;

        /// <summary>The 16-byte AEAD tag length (AES-256-GCM).</summary>
        public const int TagLength = 16;

        /// <summary>The AEAD nonce length (12 bytes: 4 zero bytes followed by the 8-byte big-endian message counter).</summary>
        public const int NonceLength = 12;
    }
}
