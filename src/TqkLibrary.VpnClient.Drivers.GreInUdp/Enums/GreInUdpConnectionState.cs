namespace TqkLibrary.VpnClient.Drivers.GreInUdp.Enums
{
    /// <summary>The lifecycle state of a <see cref="GreInUdpConnection"/>, surfaced via its StateChanged event.</summary>
    public enum GreInUdpConnectionState
    {
        /// <summary>Not connected (initial state, or after a clean/forced teardown).</summary>
        Disconnected = 0,

        /// <summary>Opening the UDP transport and binding the GRE-in-UDP channel.</summary>
        Connecting = 1,

        /// <summary>The tunnel is up and carrying traffic.</summary>
        Connected = 2,

        /// <summary>The link is being re-established (reserved — plain encap has no control plane to detect loss).</summary>
        Reconnecting = 3,
    }
}
