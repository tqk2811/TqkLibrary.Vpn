using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Drivers.Ssh
{
    /// <summary>
    /// The single L3 session of a VPN-over-SSH connection. <see cref="PacketChannel"/> is the stable facade and
    /// <see cref="Config"/> is the static config (SSH does no in-tunnel address negotiation, so neither changes across a
    /// reconnect). Mirrors <c>VtunVpnSession</c>.
    /// </summary>
    public sealed class SshVpnSession : IVpnSession
    {
        /// <summary>Creates a session over the given (stable) channel and config.</summary>
        public SshVpnSession(IPacketChannel packetChannel, TunnelConfig config)
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
