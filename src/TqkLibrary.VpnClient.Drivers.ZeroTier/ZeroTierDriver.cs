using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.ZeroTier.Config;
using TqkLibrary.VpnClient.Drivers.ZeroTier.Transport;

namespace TqkLibrary.VpnClient.Drivers.ZeroTier
{
    /// <summary>
    /// The ZeroTier (VL1/VL2) protocol driver. It is configured with a static <see cref="ZeroTierConfig"/> (this node's
    /// identity + the upstream node/controller's, the network id, the optional static overlay IP); the connect-time
    /// <see cref="VpnEndpoint"/> supplies the node/controller host/port. The overlay address comes from the controller's
    /// network config (or is pinned), so the tunnel address / routes / MTU are <see cref="AddressAssignment.OutOfBand"/>.
    /// L2 Ethernet mesh over UDP — VL1 secures the path (Curve25519 → Salsa20/12 + Poly1305), VL2 carries the Ethernet
    /// frames (EXT_FRAME); planet/moon root discovery is bypassed (peer with the node/controller directly).
    /// </summary>
    public sealed class ZeroTierDriver : IVpnProtocolDriver
    {
        readonly ZeroTierConfig _config;
        readonly ZeroTierReconnectOptions? _reconnectOptions;
        readonly IZeroTierTransportFactory? _transportFactory;
        readonly ILoggerFactory? _loggerFactory;

        /// <summary>
        /// Creates the driver. <paramref name="config"/> is the static client profile; <paramref name="reconnectOptions"/>
        /// tunes (or disables) auto-reconnect; <paramref name="transportFactory"/> overrides the UDP transport (an
        /// in-process loopback drives the driver offline in tests). <paramref name="loggerFactory"/> receives diagnostic
        /// traces (null = no logging).
        /// </summary>
        public ZeroTierDriver(ZeroTierConfig config,
            ZeroTierReconnectOptions? reconnectOptions = null,
            IZeroTierTransportFactory? transportFactory = null,
            ILoggerFactory? loggerFactory = null)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _reconnectOptions = reconnectOptions;
            _transportFactory = transportFactory;
            _loggerFactory = loggerFactory;
        }

        /// <inheritdoc/>
        public string Name => ZeroTierDriverConstants.DriverName;

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L2Ethernet,                 // Ethernet frames as EXT_FRAME messages
            UsesPpp = false,
            MultiHostModel = MultiHostModel.None,                // single member, one network membership
            TransportKinds = VpnTransportKind.Udp,               // ZeroTier VL1 is UDP
            SecurityKinds = VpnSecurityKind.None,                // Salsa20/12 + Poly1305 (no standard kind matches)
            AuthMethods = VpnAuthMethod.Certificate,             // Curve25519/Ed25519 identity + certificate of membership
            AddressAssignment = AddressAssignment.OutOfBand,     // the controller assigns (or the config pins) the overlay address
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            if (endpoint is null) throw new ArgumentNullException(nameof(endpoint));

            IZeroTierTransportFactory factory = _transportFactory ?? new ZeroTierSocketTransportFactory();
            int port = endpoint.Port > 0 ? endpoint.Port : ZeroTierDriverConstants.DefaultPort;
            var connection = new ZeroTierConnection(endpoint.Host, port, _config, factory,
                reconnectOptions: _reconnectOptions,
                addressFamilyPreference: endpoint.AddressFamilyPreference,
                loggerFactory: _loggerFactory);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);
                var session = new ZeroTierVpnSession(connection.PacketChannel, connection.Config);
                return new ZeroTierVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
