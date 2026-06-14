using System.Net;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;

namespace TqkLibrary.Vpn.Drivers.L2tpIpsec.Models
{
    /// <summary>
    /// The result of opening an additional L2TP session on a live tunnel: its own PPP packet channel and the
    /// address/DNS that session's IPCP negotiated (independent of the primary session's).
    /// </summary>
    public sealed class L2tpIpsecAdditionalSession
    {
        /// <summary>Creates the descriptor for a freshly established additional session.</summary>
        public L2tpIpsecAdditionalSession(IPacketChannel packetChannel, IPAddress assignedAddress, IPAddress? assignedDns)
        {
            PacketChannel = packetChannel;
            AssignedAddress = assignedAddress;
            AssignedDns = assignedDns;
        }

        /// <summary>The L3 packet channel carrying this session's IP traffic.</summary>
        public IPacketChannel PacketChannel { get; }

        /// <summary>The IP address this session's IPCP assigned.</summary>
        public IPAddress AssignedAddress { get; }

        /// <summary>The DNS server this session's IPCP pushed, if any.</summary>
        public IPAddress? AssignedDns { get; }
    }
}
