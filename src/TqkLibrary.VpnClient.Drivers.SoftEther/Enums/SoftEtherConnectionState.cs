namespace TqkLibrary.VpnClient.Drivers.SoftEther.Enums
{
    /// <summary>The lifecycle state of a <see cref="SoftEtherConnection"/>, surfaced via its StateChanged event.</summary>
    public enum SoftEtherConnectionState
    {
        /// <summary>Not connected (initial state, or after a clean/forced teardown).</summary>
        Disconnected = 0,

        /// <summary>Connecting: TLS + the watermark/hello/login control handshake, then the DHCP lease.</summary>
        Connecting = 1,

        /// <summary>The tunnel is up and carrying Ethernet traffic (an IP leased over DHCP, bridged to L3).</summary>
        Connected = 2,

        /// <summary>The session was declared dead (transport fault / stream closed); a reconnect may follow.</summary>
        Reconnecting = 3,
    }
}
