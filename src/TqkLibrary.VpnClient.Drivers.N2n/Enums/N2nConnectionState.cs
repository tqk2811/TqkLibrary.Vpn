namespace TqkLibrary.VpnClient.Drivers.N2n.Enums
{
    /// <summary>The lifecycle state of an <see cref="N2nConnection"/> (mirrors the other drivers' state enums).</summary>
    public enum N2nConnectionState
    {
        /// <summary>Not connected (initial state, or after a teardown / a final reconnect failure).</summary>
        Disconnected,
        /// <summary>Running the REGISTER_SUPER exchange with the supernode.</summary>
        Connecting,
        /// <summary>The edge is registered and the L2 data plane is carrying traffic.</summary>
        Connected,
        /// <summary>The link dropped and the supervisor is attempting to re-register.</summary>
        Reconnecting,
    }
}
