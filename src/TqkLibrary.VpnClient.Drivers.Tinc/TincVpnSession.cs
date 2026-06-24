using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Drivers.Tinc
{
    /// <summary>
    /// The single L3 session of a tinc connection. <see cref="PacketChannel"/> is the stable facade and
    /// <see cref="Config"/> is the static config (tinc does no in-tunnel negotiation, so neither changes across a
    /// re-key or a reconnect). Mirrors <c>NebulaVpnSession</c>.
    /// </summary>
    public sealed class TincVpnSession : IVpnSession
    {
        /// <summary>Creates a session over the given (stable) channel and config.</summary>
        public TincVpnSession(IPacketChannel packetChannel, TunnelConfig config)
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
