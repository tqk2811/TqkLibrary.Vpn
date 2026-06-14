namespace TqkLibrary.VpnClient.OpenVpn
{
    /// <summary>
    /// Retransmit + window policy for the OpenVPN control-channel reliability layer: how long to wait before resending
    /// an unacknowledged control packet, how that delay grows after each resend, the cap it is clamped to, how many
    /// resends before the channel is declared dead, and how many control packets may be in flight (unacked) per
    /// direction. Defaults mirror OpenVPN's behaviour: a fixed ~1s interval (<see cref="BackoffMultiplier"/> 1.0) and a
    /// small window.
    /// </summary>
    public sealed class OpenVpnReliabilityOptions
    {
        /// <summary>Delay before the first retransmit of an unacknowledged control packet (default 1s).</summary>
        public TimeSpan Interval { get; set; } = TimeSpan.FromSeconds(1);

        /// <summary>How many times a packet is resent before the send window declares the peer dead; 0 = unbounded.</summary>
        public int MaxRetransmits { get; set; }

        /// <summary>Factor the interval grows by after each resend (1.0 = fixed interval, no backoff).</summary>
        public double BackoffMultiplier { get; set; } = 1.0;

        /// <summary>Upper bound the backed-off interval is clamped to (default 8s).</summary>
        public TimeSpan MaxInterval { get; set; } = TimeSpan.FromSeconds(8);

        /// <summary>Max control packets in flight (queued but unacked) per direction (default 8 — one P_ACK can clear a full window).</summary>
        public int WindowSize { get; set; } = 8;

        /// <summary>
        /// The delay before the resend that follows <paramref name="resends"/> already-completed resends of the same
        /// packet: <c>Interval × BackoffMultiplier^resends</c>, clamped at <see cref="MaxInterval"/>. <paramref name="resends"/>
        /// 0 ⇒ the base <see cref="Interval"/> (the first retransmit).
        /// </summary>
        public TimeSpan IntervalFor(int resends)
            => TimeSpan.FromMilliseconds(Math.Min(
                MaxInterval.TotalMilliseconds,
                Interval.TotalMilliseconds * Math.Pow(BackoffMultiplier, Math.Max(0, resends))));
    }
}
