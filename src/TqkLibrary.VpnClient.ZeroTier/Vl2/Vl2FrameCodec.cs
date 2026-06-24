using System.Buffers.Binary;
using TqkLibrary.VpnClient.ZeroTier.Identity.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl2.Models;

namespace TqkLibrary.VpnClient.ZeroTier.Vl2
{
    /// <summary>
    /// Encodes and decodes the body of a VL1 <c>FRAME</c> verb — a VL2 Ethernet frame carried over VL1. The body is
    /// <c>networkId(8) || etherType(2) || frameData</c> (no flags byte). This codec also derives the per-network
    /// Ethernet MAC of a node, which is how the driver rebuilds the L2 header for the Ethernet fabric. The fuller
    /// <c>EXT_FRAME</c> form (explicit dst/src MAC + optional COM) is handled by <see cref="Vl2ExtFrameCodec"/>.
    /// </summary>
    public sealed class Vl2FrameCodec
    {
        const int FixedPrefix = NetworkId.SizeInBytes + 2; // 10

        /// <summary>Serialises the FRAME body (the bytes after the verb byte).</summary>
        public byte[] Encode(Vl2Frame frame)
        {
            if (frame is null) throw new ArgumentNullException(nameof(frame));
            byte[] body = new byte[FixedPrefix + frame.FrameData.Length];
            int o = 0;
            frame.Network.Write(body.AsSpan(o, NetworkId.SizeInBytes));
            o += NetworkId.SizeInBytes;
            BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(o, 2), frame.EtherType);
            o += 2;
            frame.FrameData.CopyTo(body.AsSpan(o));
            return body;
        }

        /// <summary>Parses a FRAME body. Returns false if shorter than the 10-byte fixed prefix.</summary>
        public bool TryDecode(ReadOnlySpan<byte> body, out Vl2Frame frame)
        {
            frame = new Vl2Frame();
            if (body.Length < FixedPrefix) return false;
            int o = 0;
            frame.Network = NetworkId.Read(body.Slice(o, NetworkId.SizeInBytes));
            o += NetworkId.SizeInBytes;
            frame.EtherType = BinaryPrimitives.ReadUInt16BigEndian(body.Slice(o, 2));
            o += 2;
            frame.FrameData = body.Slice(o).ToArray();
            return true;
        }

        /// <summary>
        /// Derives a node's 48-bit Ethernet MAC for a given network, the ZeroTier way: the low 40 bits are the node
        /// address and the top octet is seeded from the network id then forced to a locally-administered, unicast
        /// value (I/G bit cleared, U/L bit set). This keeps each node's MAC unique per-network yet deterministic, so
        /// both ends agree without an ARP exchange for the gateway.
        /// </summary>
        public byte[] DeriveMac(ZeroTierAddress address, NetworkId network)
        {
            // Mix the network id's bytes into a seed for the first octet (clean-room of ZeroTier's MAC::fromAddress).
            ulong nwid = network.Value;
            byte first = (byte)(((byte)(nwid >> 56)) ^ ((byte)(nwid >> 48)) ^ ((byte)(nwid >> 40)) ^ ((byte)(nwid >> 32))
                              ^ ((byte)(nwid >> 24)) ^ ((byte)(nwid >> 16)) ^ ((byte)(nwid >> 8)) ^ (byte)nwid);
            first = (byte)((first & 0xFE) | 0x02); // unicast (clear I/G bit 0), locally administered (set U/L bit 1)
            if (first == 0x52) first = 0x32;        // avoid the common 52:.. prefix collision, per ZeroTier

            byte[] mac = new byte[6];
            mac[0] = first;
            address.Write(mac.AsSpan(1, ZeroTierAddress.SizeInBytes)); // low 40 bits = node address
            return mac;
        }
    }
}
