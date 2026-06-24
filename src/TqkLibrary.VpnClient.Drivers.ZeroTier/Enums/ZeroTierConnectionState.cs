namespace TqkLibrary.VpnClient.Drivers.ZeroTier.Enums
{
    /// <summary>The lifecycle state of a <see cref="ZeroTierConnection"/> (mirrors the other drivers' state enums).</summary>
    public enum ZeroTierConnectionState
    {
        /// <summary>Not connected (initial state, or after a teardown / a final reconnect failure).</summary>
        Disconnected,
        /// <summary>Running the VL1 HELLO ⇄ OK handshake and the VL2 network join.</summary>
        Connecting,
        /// <summary>The VL1 session is up, the network is joined, and the L2 data plane is carrying traffic.</summary>
        Connected,
        /// <summary>The link dropped and the supervisor is attempting to re-establish.</summary>
        Reconnecting,
    }
}
