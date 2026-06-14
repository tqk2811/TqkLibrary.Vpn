using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.IpStack;

namespace TqkLibrary.VpnClient.Sockets.Extensions
{
    /// <summary>Convenience helpers that build the userspace socket layer over a VPN session.</summary>
    public static class VpnSessionSocketsExtensions
    {
        /// <summary>Creates a userspace TCP/IP stack bound to the session's packet channel and assigned address.</summary>
        public static TcpIpStack CreateTcpStack(this IVpnSession session)
        {
            if (session.Config.AssignedAddress == null)
                throw new InvalidOperationException("The session has no assigned address.");
            return new TcpIpStack(session.PacketChannel, session.Config.AssignedAddress);
        }
    }
}
