using System.Net;

namespace TqkLibrary.VpnClient.Drivers.SoftEther.Models
{
    /// <summary>Raised after a successful SoftEther auto-reconnect, carrying the (re-)leased address and whether it changed.</summary>
    public sealed class SoftEtherReconnectInfo
    {
        /// <summary>Creates the info with the new tunnel address and whether it differs from the previous one.</summary>
        public SoftEtherReconnectInfo(IPAddress address, bool addressChanged)
        {
            Address = address;
            AddressChanged = addressChanged;
        }

        /// <summary>The tunnel IP after the reconnect (DHCP may have leased a different one).</summary>
        public IPAddress Address { get; }

        /// <summary>True when the leased address differs from the one held before the drop.</summary>
        public bool AddressChanged { get; }
    }
}
