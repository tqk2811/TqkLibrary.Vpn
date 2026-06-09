using System.Net;

namespace TqkLibrary.Vpn.Drivers.Sstp.Models
{
    /// <summary>Describes a successful auto-reconnect: the freshly assigned address and whether it changed from before.</summary>
    public sealed class SstpReconnectInfo
    {
        /// <summary>Creates the info for a completed reconnect.</summary>
        public SstpReconnectInfo(IPAddress assignedAddress, bool addressChanged)
        {
            AssignedAddress = assignedAddress;
            AddressChanged = addressChanged;
        }

        /// <summary>The IP address the server assigned on the new tunnel.</summary>
        public IPAddress AssignedAddress { get; }

        /// <summary>
        /// True if the new address differs from the previous one. When true, in-tunnel sockets bound to the old
        /// address are stale and the consumer must rebuild its IP stack; same-address reconnects keep working.
        /// </summary>
        public bool AddressChanged { get; }
    }
}
