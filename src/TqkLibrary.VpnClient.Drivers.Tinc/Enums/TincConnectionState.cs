namespace TqkLibrary.VpnClient.Drivers.Tinc.Enums
{
    /// <summary>The lifecycle state of a <see cref="TincConnection"/> (mirrors the other drivers' state enums).</summary>
    public enum TincConnectionState
    {
        /// <summary>No tunnel (initial / after teardown).</summary>
        Disconnected,

        /// <summary>Running the meta-connection ID + SPTPS handshake and the data-plane key exchange.</summary>
        Connecting,

        /// <summary>Tunnel up and carrying traffic.</summary>
        Connected,

        /// <summary>The tunnel dropped and the supervisor is re-establishing it.</summary>
        Reconnecting,
    }
}
