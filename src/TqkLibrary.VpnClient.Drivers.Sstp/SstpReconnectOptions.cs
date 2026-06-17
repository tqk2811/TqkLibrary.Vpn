using System;
using System.Threading;
using TqkLibrary.VpnClient.Drivers.Core.Models;

namespace TqkLibrary.VpnClient.Drivers.Sstp
{
    /// <summary>
    /// Auto-reconnect policy for an <see cref="SstpConnection"/>. Reconnect kicks in only after an initial successful
    /// connect, when the tunnel drops (read loop ended, missed Echo-Responses, or a server Call-Disconnect/Call-Abort).
    /// Enabled by default; set <see cref="VpnReconnectOptions.Enabled"/> to false to keep single-shot behaviour. The
    /// backoff/jitter/max-attempts knobs live on the shared <see cref="VpnReconnectOptions"/> base (roadmap F.6); this
    /// named type adds the SSTP-specific <see cref="ReadTimeout"/> knob and is kept for the driver's public API.
    /// </summary>
    public sealed class SstpReconnectOptions : VpnReconnectOptions
    {
        /// <summary>
        /// Caps how long a single SSTP read may block without progress before the tunnel is treated as dropped (a server
        /// that hangs mid-handshake or mid-data — roadmap P1.5). Set to <see cref="Timeout.InfiniteTimeSpan"/> to disable.
        /// The default (60 s) sits above the 30 s keepalive interval so steady-state silence between Echoes never trips it.
        /// </summary>
        public TimeSpan ReadTimeout { get; set; } = TimeSpan.FromSeconds(60);
    }
}
