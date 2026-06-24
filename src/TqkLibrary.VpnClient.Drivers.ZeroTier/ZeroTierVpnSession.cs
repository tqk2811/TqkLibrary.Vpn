using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Drivers.ZeroTier
{
    /// <summary>
    /// The single L3 session of a ZeroTier connection. <see cref="PacketChannel"/> is the stable facade (bridged from the
    /// L2 data session via the Ethernet fabric) and <see cref="Config"/> is the effective tunnel config (overlay address,
    /// routes, MTU); neither changes across a reconnect.
    /// </summary>
    public sealed class ZeroTierVpnSession : IVpnSession
    {
        /// <summary>Creates a session over the given (stable) channel and config.</summary>
        public ZeroTierVpnSession(IPacketChannel packetChannel, TunnelConfig config)
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
