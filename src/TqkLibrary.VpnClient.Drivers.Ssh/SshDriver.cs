using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.Ssh.Config;
using TqkLibrary.VpnClient.Drivers.Ssh.Transport;

namespace TqkLibrary.VpnClient.Drivers.Ssh
{
    /// <summary>
    /// The VPN-over-SSH protocol driver. It is configured with a static <see cref="SshConfig"/> (login user, an Ed25519
    /// key or password, this client's static tunnel IP and peer); the connect-time <see cref="VpnEndpoint"/> supplies the
    /// server host/port. SSH does no in-tunnel address negotiation (the server's tun device is configured by the admin),
    /// so the tunnel address/routes come from the config (<see cref="AddressAssignment.OutOfBand"/>). Point-to-point to
    /// one OpenSSH server over TCP, <c>tun@openssh.com</c> layer-3 (bare IP packets).
    /// <para>The client needs no elevation; the server needs <c>PermitTunnel point-to-point</c> + a tun device.</para>
    /// </summary>
    public sealed class SshDriver : IVpnProtocolDriver
    {
        readonly SshConfig _config;
        readonly SshReconnectOptions? _reconnectOptions;
        readonly ISshTransportFactory? _transportFactory;
        readonly ILoggerFactory? _loggerFactory;

        /// <summary>
        /// Creates the driver. <paramref name="config"/> is the static profile; <paramref name="reconnectOptions"/> tunes
        /// (or disables) auto-reconnect; <paramref name="transportFactory"/> overrides the transport (an in-process
        /// loopback drives the driver offline in tests). <paramref name="loggerFactory"/> receives diagnostic traces.
        /// </summary>
        public SshDriver(SshConfig config,
            SshReconnectOptions? reconnectOptions = null,
            ISshTransportFactory? transportFactory = null,
            ILoggerFactory? loggerFactory = null)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _reconnectOptions = reconnectOptions;
            _transportFactory = transportFactory;
            _loggerFactory = loggerFactory;
        }

        /// <inheritdoc/>
        public string Name => SshDriverConstants.DriverName;

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L3Ip,                       // tun@openssh.com point-to-point: bare IP packets
            UsesPpp = false,
            MultiHostModel = MultiHostModel.None,                // single point-to-point tunnel
            TransportKinds = VpnTransportKind.Tcp,               // SSH rides one TCP connection
            SecurityKinds = VpnSecurityKind.None,                // SSH provides its own transport encryption (not IPsec/TLS)
            AuthMethods = VpnAuthMethod.Certificate | VpnAuthMethod.UserPassword, // ed25519 publickey + password
            AddressAssignment = AddressAssignment.OutOfBand,     // tunnel address supplied statically in the config
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));

            ISshTransportFactory factory = _transportFactory ?? new SshSocketTransportFactory();
            var connection = new SshConnection(endpoint.Host, endpoint.Port, _config, factory,
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                loggerFactory: _loggerFactory);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);
                var session = new SshVpnSession(connection.PacketChannel, connection.Config);
                return new SshVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
