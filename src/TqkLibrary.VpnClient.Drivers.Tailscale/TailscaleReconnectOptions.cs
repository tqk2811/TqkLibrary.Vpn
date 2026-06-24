using TqkLibrary.VpnClient.Drivers.Core.Models;

namespace TqkLibrary.VpnClient.Drivers.Tailscale
{
    /// <summary>
    /// The Tailscale driver's auto-reconnect / backoff options. Derives from the shared <see cref="VpnReconnectOptions"/>
    /// so the supervisor in <c>ReconnectingVpnConnection</c> consumes one type while the driver keeps its own named
    /// options (mirrors <c>WireGuardReconnectOptions</c> / <c>NebulaReconnectOptions</c>). A reconnect re-runs the whole
    /// flow: a fresh ts2021 control login + netmap, then a new WireGuard tunnel. Enabled by default.
    /// </summary>
    public sealed class TailscaleReconnectOptions : VpnReconnectOptions
    {
    }
}
