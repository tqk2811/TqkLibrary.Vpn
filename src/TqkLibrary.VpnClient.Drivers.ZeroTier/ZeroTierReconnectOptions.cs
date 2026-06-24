using TqkLibrary.VpnClient.Drivers.Core.Models;

namespace TqkLibrary.VpnClient.Drivers.ZeroTier
{
    /// <summary>
    /// The ZeroTier driver's auto-reconnect / backoff options. Derives from the shared <see cref="VpnReconnectOptions"/>
    /// so the supervisor in <c>ReconnectingVpnConnection</c> consumes one type while the driver keeps its own named
    /// options (mirrors <c>N2nReconnectOptions</c> / <c>NebulaReconnectOptions</c>). Enabled by default.
    /// </summary>
    public sealed class ZeroTierReconnectOptions : VpnReconnectOptions
    {
    }
}
