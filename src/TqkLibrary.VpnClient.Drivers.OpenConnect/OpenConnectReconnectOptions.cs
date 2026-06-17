using TqkLibrary.VpnClient.Drivers.Core.Models;

namespace TqkLibrary.VpnClient.Drivers.OpenConnect
{
    /// <summary>
    /// Auto-reconnect policy for an <see cref="OpenConnectConnection"/>. Reconnect kicks in only after an initial
    /// successful connect, when the tunnel is declared dead (the gateway closed the CSTP session, DPD presumed the peer
    /// dead, or a transport fault). Enabled by default; set <see cref="VpnReconnectOptions.Enabled"/> to false to keep
    /// single-shot behaviour. The knobs live on the shared <see cref="VpnReconnectOptions"/> base (roadmap F.6); this
    /// named type is kept for the driver's public API.
    /// </summary>
    public sealed class OpenConnectReconnectOptions : VpnReconnectOptions
    {
    }
}
