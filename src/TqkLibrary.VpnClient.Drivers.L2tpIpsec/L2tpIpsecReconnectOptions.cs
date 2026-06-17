using TqkLibrary.VpnClient.Drivers.Core.Models;

namespace TqkLibrary.VpnClient.Drivers.L2tpIpsec
{
    /// <summary>
    /// Auto-reconnect policy for an <see cref="L2tpIpsecConnection"/>. Reconnect kicks in only after an initial
    /// successful connect, when the tunnel drops (DPD timeout, server Delete, L2TP teardown, or Phase 1 expiry).
    /// Enabled by default; set <see cref="VpnReconnectOptions.Enabled"/> to false to keep single-shot behaviour. The
    /// backoff/jitter/max-attempts knobs live on the shared <see cref="VpnReconnectOptions"/> base (roadmap F.6);
    /// L2TP/IPsec adds no extra knobs, so this named type is kept only for the driver's public API.
    /// </summary>
    public sealed class L2tpIpsecReconnectOptions : VpnReconnectOptions
    {
    }
}
