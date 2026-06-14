using TqkLibrary.Vpn.Abstractions.Drivers.Interfaces;
using TqkLibrary.Vpn.Abstractions.Drivers.Models;
using TqkLibrary.Vpn.Drivers.L2tpIpsec.Models;

namespace TqkLibrary.Vpn.Drivers.L2tpIpsec
{
    /// <summary>Adapts an <see cref="L2tpIpsecConnection"/> to the <see cref="IVpnConnection"/> contract (one or more sessions).</summary>
    public sealed class L2tpIpsecVpnConnection : IVpnConnection
    {
        readonly L2tpIpsecConnection _inner;
        readonly object _sessionsLock = new();
        readonly List<IVpnSession> _sessions = new();

        /// <summary>Wraps a connected <see cref="L2tpIpsecConnection"/> and its primary session.</summary>
        public L2tpIpsecVpnConnection(L2tpIpsecConnection inner, IVpnSession session)
        {
            _inner = inner;
            _sessions.Add(session);
        }

        /// <inheritdoc/>
        public IReadOnlyList<IVpnSession> Sessions
        {
            get { lock (_sessionsLock) return _sessions.ToArray(); }
        }

        /// <summary>
        /// Opens an additional PPP session on the same L2TP/IPsec tunnel (RFC 2661 multi-session). Best-effort: most
        /// remote-access servers permit only the primary session and reject the call, surfaced as an exception.
        /// Additional sessions are tied to the current tunnel instance and are not re-established by an auto-reconnect.
        /// </summary>
        public async Task<IVpnSession> OpenSessionAsync(CancellationToken cancellationToken = default)
        {
            L2tpIpsecAdditionalSession opened = await _inner.OpenAdditionalSessionAsync(cancellationToken).ConfigureAwait(false);

            var config = new TunnelConfig { AssignedAddress = opened.AssignedAddress };
            if (opened.AssignedDns != null) config.DnsServers.Add(opened.AssignedDns);

            var session = new L2tpIpsecVpnSession(opened.PacketChannel, config);
            lock (_sessionsLock) _sessions.Add(session);
            return session;
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => _inner.DisposeAsync();
    }
}
