using System.Net.Security;
using TqkLibrary.Vpn.Abstractions.Drivers.Enums;
using TqkLibrary.Vpn.Abstractions.Drivers.Interfaces;
using TqkLibrary.Vpn.Abstractions.Drivers.Models;

namespace TqkLibrary.Vpn.Drivers.Sstp
{
    /// <summary>The MS-SSTP protocol driver (TLS over 443, PPP, MS-CHAPv2).</summary>
    public sealed class SstpDriver : IVpnProtocolDriver
    {
        readonly SstpReconnectOptions? _reconnectOptions;
        readonly RemoteCertificateValidationCallback? _certificateValidationCallback;
        readonly SstpTransportOptions? _transportOptions;

        /// <summary>
        /// Creates the driver; <paramref name="reconnectOptions"/> tunes (or disables) auto-reconnect,
        /// <paramref name="certificateValidationCallback"/> validates the server TLS certificate (<c>null</c> ⇒ accept
        /// any cert — the SSTP identity is bound by its crypto binding, not PKI), and <paramref name="transportOptions"/>
        /// tunes the transport read-timeout (<c>null</c> ⇒ the default stalled-server timeout).
        /// </summary>
        public SstpDriver(SstpReconnectOptions? reconnectOptions = null, RemoteCertificateValidationCallback? certificateValidationCallback = null,
            SstpTransportOptions? transportOptions = null)
        {
            _reconnectOptions = reconnectOptions;
            _certificateValidationCallback = certificateValidationCallback;
            _transportOptions = transportOptions;
        }

        /// <inheritdoc/>
        public string Name => "sstp";

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L3Ip,
            UsesPpp = true,
            MultiHostModel = MultiHostModel.None,
            TransportKinds = VpnTransportKind.Tls,
            SecurityKinds = VpnSecurityKind.Tls,
            AuthMethods = VpnAuthMethod.UserPassword,
            AddressAssignment = AddressAssignment.Ipcp,
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            var connection = new SstpConnection(endpoint.Host, endpoint.Port, reconnectOptions: _reconnectOptions,
                certificateValidationCallback: _certificateValidationCallback, transportOptions: _transportOptions);
            try
            {
                await connection.ConnectAsync(credentials.Username ?? string.Empty, credentials.Password ?? string.Empty, cancellationToken)
                    .ConfigureAwait(false);

                var config = new TunnelConfig { AssignedAddress = connection.AssignedAddress };
                if (connection.AssignedDns != null) config.DnsServers.Add(connection.AssignedDns);

                var session = new SstpVpnSession(connection.PacketChannel, config);
                connection.Reconnected += info => session.ApplyReconnect(info, connection.AssignedDns);
                return new SstpVpnConnection(connection, session);
            }
            catch
            {
                connection.Dispose();
                throw;
            }
        }
    }
}
