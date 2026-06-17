using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.SoftEther
{
    /// <summary>Adapts a <see cref="SoftEtherConnection"/> to the <see cref="IVpnConnection"/> contract (one session).</summary>
    public sealed class SoftEtherVpnConnection : IVpnConnection
    {
        readonly SoftEtherConnection _inner;
        readonly IVpnSession _session;

        /// <summary>Wraps a connected <see cref="SoftEtherConnection"/> and its single session.</summary>
        public SoftEtherVpnConnection(SoftEtherConnection inner, IVpnSession session)
        {
            _inner = inner;
            _session = session;
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => new[] { _session };

        /// <summary>
        /// This driver bridges a single host down to one L3 session (1-host bridge). SoftEther can host a whole L2
        /// broadcast domain (multiple MAC/IP stations), but that needs the multi-host EthernetAdapter (roadmap L2.7+);
        /// until then a second session has no meaning here. Always throws.
        /// </summary>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException("The SoftEther driver bridges a single L2 host to one IP session; multi-host is roadmap L2.7+.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
