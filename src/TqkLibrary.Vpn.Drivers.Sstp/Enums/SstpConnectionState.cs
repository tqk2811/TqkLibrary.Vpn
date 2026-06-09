namespace TqkLibrary.Vpn.Drivers.Sstp.Enums
{
    /// <summary>The lifecycle state of an <see cref="SstpConnection"/>, surfaced via its StateChanged event.</summary>
    public enum SstpConnectionState
    {
        /// <summary>Not connected (initial state, or after a clean/forced teardown).</summary>
        Disconnected = 0,

        /// <summary>Running the TLS / SSTP control / PPP / crypto-binding handshake.</summary>
        Connecting = 1,

        /// <summary>The tunnel is up and carrying traffic.</summary>
        Connected = 2,

        /// <summary>The link dropped (read loop ended, missed echoes, or a server Call-Disconnect); a reconnect may follow.</summary>
        Reconnecting = 3,
    }
}
