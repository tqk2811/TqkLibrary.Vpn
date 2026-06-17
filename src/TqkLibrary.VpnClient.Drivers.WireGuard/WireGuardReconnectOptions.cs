using TqkLibrary.VpnClient.Drivers.Core.Models;

namespace TqkLibrary.VpnClient.Drivers.WireGuard
{
    /// <summary>
    /// Auto-reconnect policy for a <see cref="WireGuardConnection"/>. Reconnect kicks in only after an initial
    /// successful connect, when the tunnel is declared dead (a handshake that could not be re-established within the
    /// whitepaper's <c>REKEY_ATTEMPT_TIME</c>, or a transport fault). Enabled by default; set
    /// <see cref="VpnReconnectOptions.Enabled"/> to false to keep single-shot behaviour. The knobs live on the shared
    /// <see cref="VpnReconnectOptions"/> base (roadmap F.6); this named type is kept for the driver's public API.
    /// </summary>
    public sealed class WireGuardReconnectOptions : VpnReconnectOptions
    {
    }
}
