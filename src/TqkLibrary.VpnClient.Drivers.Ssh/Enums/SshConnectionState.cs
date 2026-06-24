namespace TqkLibrary.VpnClient.Drivers.Ssh.Enums
{
    /// <summary>The lifecycle states of an <c>SshConnection</c>.</summary>
    public enum SshConnectionState
    {
        /// <summary>Not connected.</summary>
        Disconnected = 0,

        /// <summary>Running the handshake (KEX + auth + tun channel open).</summary>
        Connecting = 1,

        /// <summary>Tunnel up, carrying traffic.</summary>
        Connected = 2,

        /// <summary>Dropped; a reconnect may follow.</summary>
        Reconnecting = 3,
    }
}
