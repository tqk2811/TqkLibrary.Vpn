using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.Tinc.Config;
using TqkLibrary.VpnClient.Drivers.Tinc.Transport;

namespace TqkLibrary.VpnClient.Drivers.Tinc
{
    /// <summary>
    /// The tinc 1.1 (SPTPS) protocol driver. It is configured with a static <see cref="TincConfig"/> (this node's
    /// Ed25519 key + name, the peer's host file, this client's overlay IP/CIDR, MTU); the connect-time
    /// <see cref="VpnEndpoint"/> supplies the peer host/port when the config leaves it unset. Each node's overlay subnet
    /// is declared statically (in its host file / this config), so the tunnel address/DNS/routes come straight from the
    /// config (<see cref="AddressAssignment.OutOfBand"/>). Point-to-point to one peer (mesh discovery bypassed).
    /// </summary>
    public sealed class TincDriver : IVpnProtocolDriver
    {
        readonly TincConfig _config;
        readonly TincReconnectOptions? _reconnectOptions;
        readonly ITincTransportFactory? _transportFactory;
        readonly ILoggerFactory? _loggerFactory;

        /// <summary>
        /// Creates the driver. <paramref name="config"/> is the static profile; <paramref name="reconnectOptions"/>
        /// tunes (or disables) auto-reconnect; <paramref name="transportFactory"/> overrides the transport (an
        /// in-process loopback drives the driver offline in tests). <paramref name="loggerFactory"/> receives diagnostic
        /// traces (null = no logging).
        /// </summary>
        public TincDriver(TincConfig config,
            TincReconnectOptions? reconnectOptions = null,
            ITincTransportFactory? transportFactory = null,
            ILoggerFactory? loggerFactory = null)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _reconnectOptions = reconnectOptions;
            _transportFactory = transportFactory;
            _loggerFactory = loggerFactory;
        }

        /// <inheritdoc/>
        public string Name => "tinc";

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L3Ip,                       // router mode: bare IP packets, no link header
            UsesPpp = false,
            MultiHostModel = MultiHostModel.None,                // single point-to-point peer (static endpoint)
            TransportKinds = VpnTransportKind.Tcp | VpnTransportKind.Udp, // TCP meta-connection + UDP data plane
            SecurityKinds = VpnSecurityKind.Noise,               // SPTPS: Curve25519 ECDH + Ed25519 + ChaCha-Poly1305
            AuthMethods = VpnAuthMethod.Certificate,             // Ed25519 host keys
            AddressAssignment = AddressAssignment.OutOfBand,     // overlay subnet declared statically in host files
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));

            ITincTransportFactory factory = _transportFactory ?? new TincSocketTransportFactory();
            var connection = new TincConnection(endpoint.Host, endpoint.Port, _config, factory,
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                loggerFactory: _loggerFactory);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);
                var session = new TincVpnSession(connection.PacketChannel, connection.Config);
                return new TincVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
