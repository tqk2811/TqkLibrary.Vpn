using Microsoft.Extensions.Logging;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Drivers.Tailscale.Config;
using TqkLibrary.VpnClient.Drivers.WireGuard.Transport;
using TqkLibrary.VpnClient.Tailscale.Control;

namespace TqkLibrary.VpnClient.Drivers.Tailscale
{
    /// <summary>
    /// The Tailscale protocol driver. It is configured with a static <see cref="TailscaleConfig"/> (the coordination
    /// server URL, a preauth key and the machine/node X25519 keys). At connect time it runs the ts2021 control plane
    /// (login + register + netmap), projects the netmap onto a multi-peer WireGuard config and brings the reused
    /// WireGuard data plane up from it. The tunnel address/routes come from the netmap
    /// (<see cref="AddressAssignment.OutOfBand"/> — control-plane assigned, not in-tunnel negotiated). The connect-time
    /// <see cref="VpnEndpoint"/> is unused (the server is in the config); per-peer endpoints come from the netmap.
    /// </summary>
    public sealed class TailscaleDriver : IVpnProtocolDriver
    {
        readonly TailscaleConfig _config;
        readonly TailscaleReconnectOptions? _reconnectOptions;
        readonly IWireGuardTransportFactory? _wireGuardTransportFactory;
        readonly Func<TailscaleConfig, ITailscaleControlClient>? _controlClientFactory;
        readonly ILoggerFactory? _loggerFactory;

        /// <summary>
        /// Creates the driver. <paramref name="config"/> is the static profile; <paramref name="reconnectOptions"/>
        /// tunes (or disables) auto-reconnect; <paramref name="wireGuardTransportFactory"/> overrides the WireGuard UDP
        /// transport (an in-process loopback drives the data plane offline in tests); <paramref name="controlClientFactory"/>
        /// overrides the ts2021 control client (a fake serves a canned netmap offline in tests). <paramref name="loggerFactory"/>
        /// receives diagnostic traces.
        /// </summary>
        public TailscaleDriver(TailscaleConfig config,
            TailscaleReconnectOptions? reconnectOptions = null,
            IWireGuardTransportFactory? wireGuardTransportFactory = null,
            Func<TailscaleConfig, ITailscaleControlClient>? controlClientFactory = null,
            ILoggerFactory? loggerFactory = null)
        {
            _config = config ?? throw new ArgumentNullException(nameof(config));
            _reconnectOptions = reconnectOptions;
            _wireGuardTransportFactory = wireGuardTransportFactory;
            _controlClientFactory = controlClientFactory;
            _loggerFactory = loggerFactory;
        }

        /// <inheritdoc/>
        public string Name => "tailscale";

        /// <inheritdoc/>
        public VpnDriverCapabilities Capabilities { get; } = new VpnDriverCapabilities
        {
            LinkLayer = VpnLinkLayer.L3Ip,                       // WireGuard carries bare IP packets, no link header
            UsesPpp = false,
            MultiHostModel = MultiHostModel.RoutedPrefixes,      // multi-peer crypto-routing from the netmap allowed-IPs
            TransportKinds = VpnTransportKind.Udp,               // data plane is WireGuard over UDP
            SecurityKinds = VpnSecurityKind.Noise,               // ts2021 Noise IK control + Noise_IKpsk2 data
            AuthMethods = VpnAuthMethod.PreSharedKey,            // preauth key login
            AddressAssignment = AddressAssignment.OutOfBand,     // overlay address assigned by the control plane (netmap)
        };

        /// <inheritdoc/>
        public async Task<IVpnConnection> ConnectAsync(VpnEndpoint endpoint, VpnCredentials credentials, CancellationToken cancellationToken = default)
        {
            var connection = new TailscaleConnection(_config, _reconnectOptions, _wireGuardTransportFactory, _controlClientFactory, _loggerFactory);
            try
            {
                await connection.ConnectAsync(cancellationToken).ConfigureAwait(false);
                var session = new TailscaleVpnSession(connection.PacketChannel, connection.Config);
                return new TailscaleVpnConnection(connection, session);
            }
            catch
            {
                await connection.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
    }
}
