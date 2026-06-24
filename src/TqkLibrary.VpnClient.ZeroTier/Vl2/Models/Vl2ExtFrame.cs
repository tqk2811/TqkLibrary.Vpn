using TqkLibrary.VpnClient.ZeroTier.Identity.Models;

namespace TqkLibrary.VpnClient.ZeroTier.Vl2.Models
{
    /// <summary>
    /// The decoded body of a VL1 <c>EXT_FRAME</c> verb — a VL2 Ethernet frame carried over VL1 with explicit MAC
    /// addresses (and, optionally, an attached certificate of membership). Unlike <c>FRAME</c>, EXT_FRAME spells out the
    /// destination and source MACs on the wire (used for broadcast/bridged traffic and when a node must attach its COM to
    /// prove membership). Wire body:
    /// <c>networkId(8) || flags(1) || [com if flags&amp;0x01] || destMac(6) || srcMac(6) || etherType(2) || frameData</c>.
    /// </summary>
    public sealed class Vl2ExtFrame
    {
        /// <summary>Flag bit: a certificate of membership is attached immediately after the flags byte.</summary>
        public const byte FlagComAttached = 0x01;

        /// <summary>The virtual network this frame belongs to.</summary>
        public NetworkId Network { get; set; }

        /// <summary>The EXT_FRAME flags byte (bit 0 = COM attached).</summary>
        public byte Flags { get; set; }

        /// <summary>The attached certificate of membership blob when <see cref="Flags"/> has <see cref="FlagComAttached"/>; else null.</summary>
        public byte[]? CertificateOfMembership { get; set; }

        /// <summary>The destination Ethernet MAC (6 bytes).</summary>
        public byte[] DestinationMac { get; set; } = new byte[6];

        /// <summary>The source Ethernet MAC (6 bytes).</summary>
        public byte[] SourceMac { get; set; } = new byte[6];

        /// <summary>The Ethernet frame's EtherType.</summary>
        public ushort EtherType { get; set; }

        /// <summary>The Ethernet payload (no MAC header, no FCS).</summary>
        public byte[] FrameData { get; set; } = System.Array.Empty<byte>();

        /// <summary>The source node address (from the VL1 header); not part of the body but tracked for routing.</summary>
        public ZeroTierAddress Source { get; set; }

        /// <summary>The destination node address (from the VL1 header).</summary>
        public ZeroTierAddress Destination { get; set; }
    }
}
