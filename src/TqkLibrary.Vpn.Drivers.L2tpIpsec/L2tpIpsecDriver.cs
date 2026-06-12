using TqkLibrary.Vpn.Abstractions.Drivers.Enums;
using TqkLibrary.Vpn.Abstractions.Drivers.Interfaces;
using TqkLibrary.Vpn.Abstractions.Drivers.Models;

namespace TqkLibrary.Vpn.Drivers.L2tpIpsec
{
    /// <summary>The L2TP/IPsec protocol driver (IKEv1 PSK over NAT-T, ESP transport mode, L2TP, PPP/MS-CHAPv2).</summary>
    public sealed class L2tpIpsecDriver : IVpnProtocolDriver
    {
        readonly L2tpIpsecReconnectOptions? _reconnectOptions;
        readonly L2tpIpsecTimeoutOptions? _timeoutOptions;

        /// <summary>
        /// Creates the driver; <paramref name="reconnectOptions"/> tunes (or disables) auto-reconnect and
        /// <paramref name="timeoutOptions"/> tunes the IKE/L2TP handshake timeouts and retransmit caps.
        /// </summary>
        public L2tpIpsecDriver(L2tpIpsecReconnectOptions? reconnectOptions = null, L2tpIpsecTimeoutOptions? timeoutOptions = null)
        {
            _reconnectOptions = reconnectOptions;
            _timeoutOptions = timeoutOptions;
        }

        /// <inheritdoc/>
        public string Name => "l2tp-ipsec";

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L3Ip,
            UsesPpp = true,
            MultiHostModel = MultiHostModel.None,
            TransportKinds = VpnTransportKind.Udp,
            SecurityKinds = VpnSecurityKind.Esp,
            AuthMethods = VpnAuthMethod.UserPassword | VpnAuthMethod.PreSharedKey,
            AddressAssignment = AddressAssignment.Ipcp,
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            byte[]? psk = credentials.PreSharedKey;
            if (psk is null || psk.Length == 0)
                throw new ArgumentException(
                    "L2TP/IPsec requires a pre-shared key. Set VpnCredentials.PreSharedKey (VPN Gate's group PSK is \"vpn\").",
                    nameof(credentials));

            var connection = new L2tpIpsecConnection(endpoint.Host, psk, reconnectOptions: _reconnectOptions, timeoutOptions: _timeoutOptions);
            try
            {
                await connection.ConnectAsync(credentials.Username ?? string.Empty, credentials.Password ?? string.Empty, cancellationToken)
                    .ConfigureAwait(false);

                var config = new TunnelConfig { AssignedAddress = connection.AssignedAddress };
                if (connection.AssignedDns != null) config.DnsServers.Add(connection.AssignedDns);

                var session = new L2tpIpsecVpnSession(connection.PacketChannel, config);
                connection.Reconnected += info => session.ApplyReconnect(info, connection.AssignedDns);
                return new L2tpIpsecVpnConnection(connection, session);
            }
            catch
            {
                connection.Dispose();
                throw;
            }
        }
    }
}
