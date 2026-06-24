namespace TqkLibrary.VpnClient.Drivers.Tailscale.Enums
{
    /// <summary>The lifecycle states of a <see cref="TailscaleConnection"/> (mapped onto the reconnect supervisor).</summary>
    public enum TailscaleConnectionState
    {
        /// <summary>No control session and no tunnel.</summary>
        Disconnected = 0,

        /// <summary>Running the ts2021 control login + netmap fetch and bringing the WireGuard tunnel up.</summary>
        Connecting = 1,

        /// <summary>Control done, netmap applied, WireGuard tunnel carrying traffic.</summary>
        Connected = 2,

        /// <summary>Re-running control + WireGuard after a link drop.</summary>
        Reconnecting = 3,
    }
}
