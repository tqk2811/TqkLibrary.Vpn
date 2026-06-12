namespace TqkLibrary.Vpn.Drivers.Sstp
{
    /// <summary>
    /// Low-level transport tuning for an <see cref="SstpTransport"/>. Currently just the read-timeout that bounds each
    /// <see cref="SstpTransport.ReadPacketAsync"/>: it detects a server that stops sending mid-handshake or mid-data
    /// (the TLS stream stays open but no bytes arrive) instead of blocking until the stream is finally closed/cancelled.
    /// </summary>
    public sealed class SstpTransportOptions
    {
        /// <summary>
        /// Maximum time a single <see cref="SstpTransport.ReadPacketAsync"/> may wait for a complete packet before it
        /// throws <see cref="TimeoutException"/>. <see cref="Timeout.InfiniteTimeSpan"/> (the default) disables the
        /// timeout, preserving the read-until-closed behaviour. For a live tunnel it must exceed the keepalive Echo
        /// interval so a healthy-but-idle tunnel — which still exchanges an Echo every interval — never trips it.
        /// </summary>
        public TimeSpan ReadTimeout { get; set; } = Timeout.InfiniteTimeSpan;
    }
}
