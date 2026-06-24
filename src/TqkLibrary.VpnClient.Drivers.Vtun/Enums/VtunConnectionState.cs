namespace TqkLibrary.VpnClient.Drivers.Vtun.Enums
{
    /// <summary>The lifecycle states of a <c>VtunConnection</c>.</summary>
    public enum VtunConnectionState
    {
        /// <summary>Not connected.</summary>
        Disconnected = 0,

        /// <summary>Running the handshake (auth + flags).</summary>
        Connecting = 1,

        /// <summary>Tunnel up, carrying traffic.</summary>
        Connected = 2,

        /// <summary>Dropped; a reconnect may follow.</summary>
        Reconnecting = 3,
    }
}
