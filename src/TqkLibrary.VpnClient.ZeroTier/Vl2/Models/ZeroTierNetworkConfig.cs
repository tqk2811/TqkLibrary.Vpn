using System.Collections.Generic;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl2.Models;

namespace TqkLibrary.VpnClient.ZeroTier.Vl2.Models
{
    /// <summary>
    /// A network configuration as issued by a ZeroTier controller — the decoded subset of the controller's dictionary
    /// the client needs to bring an L2 overlay up. The controller dictionary holds far more (rules, capabilities, tags,
    /// DNS, multicast limits); this captures the fields that drive the data plane: the network id, the static IP(s)
    /// assigned to this member (with their CIDR prefix carried in the InetAddress port field), the managed routes, the
    /// MTU, and the raw certificate-of-membership blob the client must echo when proving membership to peers.
    /// </summary>
    public sealed class ZeroTierNetworkConfig
    {
        /// <summary>The network this configuration is for.</summary>
        public NetworkId Network { get; set; }

        /// <summary>The static IP address(es) the controller assigned to this member (the <c>I</c> key). The
        /// <see cref="InetAddressValue.Port"/> field carries the subnet prefix length, not a UDP port.</summary>
        public IReadOnlyList<InetAddressValue> AssignedAddresses { get; set; } = new List<InetAddressValue>();

        /// <summary>The managed routes the controller pushed (the <c>RT</c> key), as (target, via) pairs (via may be nil).</summary>
        public IReadOnlyList<(InetAddressValue Target, InetAddressValue Via)> Routes { get; set; }
            = new List<(InetAddressValue, InetAddressValue)>();

        /// <summary>The overlay MTU (the <c>mtu</c> key); 2800 (ZeroTier default) when the controller does not set it.</summary>
        public int Mtu { get; set; } = 2800;

        /// <summary>The certificate-of-membership blob (the <c>C</c> or legacy <c>com</c> key), or null when the network
        /// is public / no COM was issued. The client stores this and echoes it to peers; it does not parse or re-sign it.</summary>
        public byte[]? CertificateOfMembership { get; set; }

        /// <summary>The network name (the <c>n</c> key), or null.</summary>
        public string? Name { get; set; }

        /// <summary>True if the controller assigned at least one static IP (the join produced a usable overlay address).</summary>
        public bool HasAssignedAddress => AssignedAddresses.Count > 0;
    }
}
