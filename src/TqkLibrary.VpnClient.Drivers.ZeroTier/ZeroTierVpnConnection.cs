using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.ZeroTier
{
    /// <summary>Adapts a <see cref="ZeroTierConnection"/> to the <see cref="IVpnConnection"/> contract (one session).</summary>
    public sealed class ZeroTierVpnConnection : IVpnConnection
    {
        readonly ZeroTierConnection _inner;
        readonly IVpnSession _session;

        /// <summary>Wraps a connected <see cref="ZeroTierConnection"/> and its single session.</summary>
        public ZeroTierVpnConnection(ZeroTierConnection inner, IVpnSession session)
        {
            _inner = inner;
            _session = session;
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => new[] { _session };

        /// <summary>
        /// ZeroTier carries a single overlay L2 session per network membership; a second session has no protocol meaning
        /// here. Always throws.
        /// </summary>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException("ZeroTier carries a single overlay L2 session; additional sessions are not supported.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
