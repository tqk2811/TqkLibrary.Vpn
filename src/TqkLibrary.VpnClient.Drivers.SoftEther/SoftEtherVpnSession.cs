using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;

namespace TqkLibrary.VpnClient.Drivers.SoftEther
{
    /// <summary>
    /// The single L3 session of a SoftEther connection. <see cref="PacketChannel"/> is the stable facade (it survives a
    /// reconnect) and <see cref="Config"/> is the DHCP-leased tunnel configuration.
    /// </summary>
    public sealed class SoftEtherVpnSession : IVpnSession
    {
        /// <summary>Creates a session over the given (stable) channel and leased config.</summary>
        public SoftEtherVpnSession(IPacketChannel packetChannel, TunnelConfig config)
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
