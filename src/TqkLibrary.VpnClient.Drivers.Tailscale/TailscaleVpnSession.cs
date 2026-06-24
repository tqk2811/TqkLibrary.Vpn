using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Drivers.Tailscale
{
    /// <summary>
    /// The single L3 session of a Tailscale connection. <see cref="PacketChannel"/> is the stable facade over the
    /// reused WireGuard data plane and <see cref="Config"/> is the tunnel config derived from the netmap (the overlay
    /// address, the routes from the peers' allowed-IPs, the MTU). Neither changes across a WireGuard rekey or reconnect.
    /// </summary>
    public sealed class TailscaleVpnSession : IVpnSession
    {
        /// <summary>Creates a session over the given (stable) channel and netmap-derived config.</summary>
        public TailscaleVpnSession(IPacketChannel packetChannel, TunnelConfig config)
        {
            PacketChannel = packetChannel;
            Config = config;
        }

        /// <inheritdoc/>
        public TunnelConfig Config { get; }

        /// <inheritdoc/>
        public IPacketChannel PacketChannel { get; }

        /// <inheritdoc/>
        public ValueTask DisposeAsync() => default;
    }
}
