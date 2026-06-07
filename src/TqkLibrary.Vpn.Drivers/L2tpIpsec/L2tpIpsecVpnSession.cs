using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.Abstractions.Drivers.Interfaces;
using TqkLibrary.Vpn.Abstractions.Drivers.Models;

namespace TqkLibrary.Vpn.Drivers.L2tpIpsec
{
    /// <summary>The single PPP/L3 session of an L2TP/IPsec connection.</summary>
    public sealed class L2tpIpsecVpnSession : IVpnSession
    {
        /// <summary>Creates a session over the given channel and config.</summary>
        public L2tpIpsecVpnSession(IPacketChannel packetChannel, TunnelConfig config)
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
