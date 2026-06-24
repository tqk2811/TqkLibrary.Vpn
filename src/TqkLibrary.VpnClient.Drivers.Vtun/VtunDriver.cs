using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.Vtun.Config;
using TqkLibrary.VpnClient.Drivers.Vtun.Transport;

namespace TqkLibrary.VpnClient.Drivers.Vtun
{
    /// <summary>
    /// The vtun (legacy tunnel daemon) protocol driver. It is configured with a static <see cref="VtunConfig"/> (host
    /// name + password, this client's static tunnel IP and peer); the connect-time <see cref="VpnEndpoint"/> supplies the
    /// server host/port. vtun does no in-tunnel address negotiation (the server's <c>up</c>/<c>down</c> scripts set its
    /// own tun device), so the tunnel address/routes come from the config (<see cref="AddressAssignment.OutOfBand"/>).
    /// Point-to-point to one host over TCP, <c>type tun</c> with <c>encrypt no</c> + <c>compress no</c>.
    /// <para>⚠️ vtun's challenge-response keys a Blowfish-ECB challenge with MD5(password); legacy/weak — interop only.</para>
    /// </summary>
    public sealed class VtunDriver : IVpnProtocolDriver
    {
        readonly VtunConfig _config;
        readonly VtunReconnectOptions? _reconnectOptions;
        readonly IVtunTransportFactory? _transportFactory;
        readonly ILoggerFactory? _loggerFactory;

        /// <summary>
        /// Creates the driver. <paramref name="config"/> is the static profile; <paramref name="reconnectOptions"/>
        /// tunes (or disables) auto-reconnect; <paramref name="transportFactory"/> overrides the transport (an
        /// in-process loopback drives the driver offline in tests). <paramref name="loggerFactory"/> receives diagnostic
        /// traces (null = no logging).
        /// </summary>
        public VtunDriver(VtunConfig config,
            VtunReconnectOptions? reconnectOptions = null,
            IVtunTransportFactory? transportFactory = null,
            ILoggerFactory? loggerFactory = null)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _reconnectOptions = reconnectOptions;
            _transportFactory = transportFactory;
            _loggerFactory = loggerFactory;
        }

        /// <inheritdoc/>
        public string Name => VtunDriverConstants.DriverName;

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L3Ip,                       // type tun: bare IP packets, no link header
            UsesPpp = false,
            MultiHostModel = MultiHostModel.None,                // single point-to-point tunnel
            TransportKinds = VpnTransportKind.Tcp,               // proto tcp (udp/tap are future work)
            SecurityKinds = VpnSecurityKind.None,                // encrypt no: cleartext data plane (auth uses Blowfish-ECB)
            AuthMethods = VpnAuthMethod.PreSharedKey,            // shared password (MD5 → Blowfish challenge)
            AddressAssignment = AddressAssignment.OutOfBand,     // tunnel address supplied statically in the config
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));

            IVtunTransportFactory factory = _transportFactory ?? new VtunSocketTransportFactory();
            var connection = new VtunConnection(endpoint.Host, endpoint.Port, _config, factory,
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                loggerFactory: _loggerFactory);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);
                var session = new VtunVpnSession(connection.PacketChannel, connection.Config);
                return new VtunVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
