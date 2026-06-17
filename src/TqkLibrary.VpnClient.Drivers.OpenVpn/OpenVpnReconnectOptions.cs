using TqkLibrary.VpnClient.Drivers.Core.Models;

namespace TqkLibrary.VpnClient.Drivers.OpenVpn
{
    /// <summary>
    /// Auto-reconnect policy for an <see cref="OpenVpnConnection"/>. Reconnect kicks in only after an initial
    /// successful connect, when the tunnel drops (a ping-restart timeout, a data-channel rekey watermark, or a transport
    /// fault). Enabled by default; set <see cref="VpnReconnectOptions.Enabled"/> to false to keep single-shot behaviour.
    /// The knobs live on the shared <see cref="VpnReconnectOptions"/> base (roadmap F.6); this named type is kept for the
    /// driver's public API.
    /// </summary>
    public sealed class OpenVpnReconnectOptions : VpnReconnectOptions
    {
    }
}
