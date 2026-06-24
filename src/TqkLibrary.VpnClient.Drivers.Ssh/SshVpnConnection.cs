using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;

namespace TqkLibrary.VpnClient.Drivers.Ssh
{
    /// <summary>Adapts an <see cref="SshConnection"/> to the <see cref="IVpnConnection"/> contract (one session).</summary>
    public sealed class SshVpnConnection : IVpnConnection
    {
        readonly SshConnection _inner;
        readonly IVpnSession _session;

        /// <summary>Wraps a connected <see cref="SshConnection"/> and its single session.</summary>
        public SshVpnConnection(SshConnection inner, IVpnSession session)
        {
            _inner = inner;
            _session = session;
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions => new[] { _session };

        /// <summary>
        /// A VPN-over-SSH connection carries a single point-to-point tunnel session (one tun@openssh.com channel); a second
        /// session has no protocol meaning here. Always throws.
        /// </summary>
        public Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException("VPN-over-SSH carries a single tunnel session; additional sessions are not supported.");

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
