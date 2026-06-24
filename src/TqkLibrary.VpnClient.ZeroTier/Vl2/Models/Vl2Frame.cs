using TqkLibrary.VpnClient.ZeroTier.Identity.Models;

namespace TqkLibrary.VpnClient.ZeroTier.Vl2.Models
{
    /// <summary>
    /// The decoded body of a VL1 <c>FRAME</c> verb — one VL2 (virtual-L2) Ethernet frame in flight. The wire body is
    /// <c>networkId(8) || etherType(2) || frameData</c> (no flags byte — verified against the real ZeroTier wire); the
    /// source/destination node addresses come from the enclosing VL1 header, and the on-wire Ethernet MAC headers are
    /// reconstructed by the driver from those addresses + the network id (see <c>Vl2FrameCodec.DeriveMac</c>).
    /// </summary>
    public sealed class Vl2Frame
    {
        /// <summary>The virtual network this frame belongs to.</summary>
        public NetworkId Network { get; set; }

        /// <summary>The Ethernet frame's EtherType (e.g. 0x0800 IPv4, 0x0806 ARP, 0x86DD IPv6).</summary>
        public ushort EtherType { get; set; }

        /// <summary>The Ethernet payload (the bytes after the EtherType — no MAC header, no FCS).</summary>
        public byte[] FrameData { get; set; } = Array.Empty<byte>();

        /// <summary>The source node address (from the VL1 header); not part of the FRAME body but tracked for routing.</summary>
        public ZeroTierAddress Source { get; set; }

        /// <summary>The destination node address (from the VL1 header).</summary>
        public ZeroTierAddress Destination { get; set; }
    }
}
