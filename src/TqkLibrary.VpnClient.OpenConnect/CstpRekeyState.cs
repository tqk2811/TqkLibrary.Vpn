using TqkLibrary.VpnClient.OpenConnect.Enums;

namespace TqkLibrary.VpnClient.OpenConnect
{
    /// <summary>
    /// CSTP session-rekey timing (the <c>X-CSTP-Rekey-Method</c> / <c>X-CSTP-Rekey-Time</c> the gateway pushes on the
    /// CONNECT response). The clock is injected (every method takes <c>nowMs</c>) so the driver pumps it from the same
    /// 1 s timer that drives DPD/keep-alive while tests stay deterministic — the same clock-inject shape as
    /// <see cref="CstpDpdState"/>.
    /// <para>
    /// After <c>X-CSTP-Rekey-Time</c> seconds the client should refresh the session (so the gateway does not time the
    /// old one out): <see cref="ShouldRekey"/> goes true, the driver runs the rekey, then marks it done with
    /// <see cref="OnRekeyDone"/>, which re-arms the timer for the next period. The rekey is disabled
    /// (<see cref="ShouldRekey"/> always false) when no period was pushed or the method is
    /// <see cref="OpenConnectRekeyMethod.None"/>.
    /// </para>
    /// </summary>
    public sealed class CstpRekeyState
    {
        readonly long _intervalMs;
        long _lastRekeyMs;

        /// <summary>
        /// Creates the timer from the pushed rekey method/seconds, seeded (last-rekey = "now") at
        /// <paramref name="nowMs"/>. <paramref name="method"/> is the parsed <c>X-CSTP-Rekey-Method</c>;
        /// <paramref name="rekeySeconds"/> is <c>X-CSTP-Rekey-Time</c> (≤ 0 disables rekey). Both
        /// <see cref="OpenConnectRekeyMethod.Ssl"/> and <see cref="OpenConnectRekeyMethod.NewTunnel"/> are honoured as a
        /// re-establish (the <c>ssl</c> TLS renegotiation is not reachable on net8/netstandard2.0 — documented fallback).
        /// </summary>
        public CstpRekeyState(OpenConnectRekeyMethod method, int rekeySeconds, long nowMs)
        {
            Method = method;
            _intervalMs = method == OpenConnectRekeyMethod.None ? 0 : Math.Max(0, rekeySeconds) * 1000L;
            _lastRekeyMs = nowMs;
        }

        /// <summary>The rekey method the gateway requested.</summary>
        public OpenConnectRekeyMethod Method { get; }

        /// <summary>True when this state actually arms a rekey timer (a non-None method and a positive period).</summary>
        public bool Enabled => _intervalMs > 0;

        /// <summary>True when a rekey is due: the rekey period has elapsed since the last (re-)establish. Always false when disabled.</summary>
        public bool ShouldRekey(long nowMs) =>
            _intervalMs > 0 && nowMs - Interlocked.Read(ref _lastRekeyMs) >= _intervalMs;

        /// <summary>Records that a rekey just completed (re-arms the timer for the next period).</summary>
        public void OnRekeyDone(long nowMs) => Interlocked.Exchange(ref _lastRekeyMs, nowMs);
    }
}
