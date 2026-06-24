using TqkLibrary.VpnClient.Drivers.Core.Models;

namespace TqkLibrary.VpnClient.Drivers.Tinc
{
    /// <summary>
    /// The tinc driver's auto-reconnect / backoff options. Derives from the shared <see cref="VpnReconnectOptions"/>
    /// so the supervisor in <c>ReconnectingVpnConnection</c> consumes one type while the driver keeps its own named
    /// options (mirrors <c>NebulaReconnectOptions</c>/<c>WireGuardReconnectOptions</c>). Enabled by default.
    /// </summary>
    public sealed class TincReconnectOptions : VpnReconnectOptions
    {
    }
}
