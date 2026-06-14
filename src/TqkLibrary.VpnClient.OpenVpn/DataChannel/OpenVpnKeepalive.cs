namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// OpenVPN keepalive timing (the pushed <c>ping</c> / <c>ping-restart</c> seconds, usually from a
    /// <see cref="OpenVpnPushReply"/>). The clock is injected (every method takes <c>nowMs</c>) so the driver pumps it
    /// from a timer while tests stay deterministic: <see cref="ShouldSendPing"/> fires when nothing has been sent for
    /// <c>ping</c> seconds; <see cref="IsPeerDead"/> fires when nothing has been received for <c>ping-restart</c>
    /// seconds (a value of 0 disables that side). Call <see cref="OnDataSent"/>/<see cref="OnDataReceived"/> for any
    /// traffic, including the ping itself.
    /// </summary>
    public sealed class OpenVpnKeepalive
    {
        readonly long _pingIntervalMs;
        readonly long _pingRestartMs;
        long _lastSentMs;
        long _lastReceivedMs;

        /// <summary>Creates the timer from the pushed seconds (0 disables that side), seeded at <paramref name="nowMs"/>.</summary>
        public OpenVpnKeepalive(int pingSeconds, int pingRestartSeconds, long nowMs)
        {
            _pingIntervalMs = Math.Max(0, pingSeconds) * 1000L;
            _pingRestartMs = Math.Max(0, pingRestartSeconds) * 1000L;
            _lastSentMs = nowMs;
            _lastReceivedMs = nowMs;
        }

        /// <summary>Records that a packet was sent (resets the ping-send timer).</summary>
        public void OnDataSent(long nowMs) => Interlocked.Exchange(ref _lastSentMs, nowMs);

        /// <summary>Records that a packet was received (resets the restart timer).</summary>
        public void OnDataReceived(long nowMs) => Interlocked.Exchange(ref _lastReceivedMs, nowMs);

        /// <summary>True when a keepalive ping is due (nothing sent for the ping interval). Disabled when ping = 0.</summary>
        public bool ShouldSendPing(long nowMs) =>
            _pingIntervalMs > 0 && nowMs - Interlocked.Read(ref _lastSentMs) >= _pingIntervalMs;

        /// <summary>True when the peer is presumed dead (nothing received for the restart timeout). Disabled when ping-restart = 0.</summary>
        public bool IsPeerDead(long nowMs) =>
            _pingRestartMs > 0 && nowMs - Interlocked.Read(ref _lastReceivedMs) >= _pingRestartMs;
    }
}
