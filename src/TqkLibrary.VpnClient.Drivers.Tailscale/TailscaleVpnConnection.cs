using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Tailscale
{
    /// <summary>Adapts a <see cref="TailscaleConnection"/> to the <see cref="IVpnConnection"/> contract (one session).</summary>
    public sealed class TailscaleVpnConnection : IVpnConnection
    {
        readonly TailscaleConnection _inner;
        readonly IVpnSession _session;

        /// <summary>Wraps a connected <see cref="TailscaleConnection"/> and its single session.</summary>
        public TailscaleVpnConnection(TailscaleConnection inner, IVpnSession session)
        {
            _inner = inner;
            _session = session;
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => new[] { _session };

        /// <summary>
        /// Tailscale carries a single L3 session over the reused WireGuard data plane (the netmap's peers are a
        /// multi-peer crypto-routing fabric, not multiple sessions). Always throws.
        /// </summary>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException("Tailscale carries a single IP session over the WireGuard data plane; additional sessions are not supported.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
