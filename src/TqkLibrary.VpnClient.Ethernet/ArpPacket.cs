using System.Net;
using System.Net.Sockets;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// Builds and reads ARP packets for IPv4-over-Ethernet (RFC 826) — the 28-byte payload that rides inside an
    /// Ethernet frame with EtherType <see cref="EthernetFrame.EtherTypeArp"/>. Only the IPv4/Ethernet binding is
    /// modeled (hardware type 1, protocol type 0x0800); other hardware/protocol pairs are out of scope. Mirrors the
    /// codec style of <see cref="EthernetFrame"/> — static, allocation-light, no instance state.
    /// </summary>
    public static class ArpPacket
    {
        /// <summary>Length in bytes of an IPv4-over-Ethernet ARP packet (htype+ptype+hlen+plen+op + 2×(MAC+IPv4)).</summary>
        public const int Length = 28;

        /// <summary>Hardware type for Ethernet (RFC 826).</summary>
        public const ushort HardwareTypeEthernet = 1;

        /// <summary>Protocol type for IPv4 (same value as the IPv4 EtherType).</summary>
        public const ushort ProtocolTypeIpv4 = 0x0800;

        /// <summary>Hardware address length for Ethernet (6 octets).</summary>
        public const byte HardwareAddressLength = 6;

        /// <summary>Protocol address length for IPv4 (4 octets).</summary>
        public const byte ProtocolAddressLength = 4;

        /// <summary>Operation code: ARP request ("who has?").</summary>
        public const ushort OperationRequest = 1;

        /// <summary>Operation code: ARP reply ("is at").</summary>
        public const ushort OperationReply = 2;

        /// <summary>Builds an ARP request asking who owns <paramref name="targetIp"/> (target hardware address left zero).</summary>
        public static byte[] BuildRequest(MacAddress senderMac, IPAddress senderIp, IPAddress targetIp)
            => Build(OperationRequest, senderMac, senderIp, MacAddress.Zero, targetIp);

        /// <summary>Builds an ARP reply telling <paramref name="targetMac"/>/<paramref name="targetIp"/> that <paramref name="senderIp"/> is at <paramref name="senderMac"/>.</summary>
        public static byte[] BuildReply(MacAddress senderMac, IPAddress senderIp, MacAddress targetMac, IPAddress targetIp)
            => Build(OperationReply, senderMac, senderIp, targetMac, targetIp);

        static byte[] Build(ushort operation, MacAddress senderMac, IPAddress senderIp, MacAddress targetMac, IPAddress targetIp)
        {
            byte[] packet = new byte[Length];
            packet[0] = (byte)(HardwareTypeEthernet >> 8);
            packet[1] = (byte)HardwareTypeEthernet;
            packet[2] = (byte)(ProtocolTypeIpv4 >> 8);
            packet[3] = (byte)(ProtocolTypeIpv4 & 0xFF);   // mask: casting the const 0x0800 straight to byte overflows
            packet[4] = HardwareAddressLength;
            packet[5] = ProtocolAddressLength;
            packet[6] = (byte)(operation >> 8);
            packet[7] = (byte)operation;
            senderMac.CopyTo(packet.AsSpan(8, MacAddress.Size));      // sender hardware address
            WriteIpv4(senderIp, packet.AsSpan(14, ProtocolAddressLength));   // sender protocol address
            targetMac.CopyTo(packet.AsSpan(18, MacAddress.Size));     // target hardware address
            WriteIpv4(targetIp, packet.AsSpan(24, ProtocolAddressLength));   // target protocol address
            return packet;
        }

        /// <summary>The 16-bit operation field (request/reply).</summary>
        public static ushort Operation(ReadOnlySpan<byte> packet) => (ushort)((packet[6] << 8) | packet[7]);

        /// <summary>The sender hardware (MAC) address.</summary>
        public static MacAddress SenderMac(ReadOnlySpan<byte> packet) => MacAddress.FromBytes(packet.Slice(8, MacAddress.Size));

        /// <summary>The sender protocol (IPv4) address.</summary>
        public static IPAddress SenderIp(ReadOnlySpan<byte> packet) => new IPAddress(packet.Slice(14, ProtocolAddressLength).ToArray());

        /// <summary>The target hardware (MAC) address (zero in a request).</summary>
        public static MacAddress TargetMac(ReadOnlySpan<byte> packet) => MacAddress.FromBytes(packet.Slice(18, MacAddress.Size));

        /// <summary>The target protocol (IPv4) address.</summary>
        public static IPAddress TargetIp(ReadOnlySpan<byte> packet) => new IPAddress(packet.Slice(24, ProtocolAddressLength).ToArray());

        /// <summary>True if <paramref name="packet"/> is a well-formed IPv4-over-Ethernet ARP packet this codec understands.</summary>
        public static bool IsIpv4OverEthernet(ReadOnlySpan<byte> packet)
            => packet.Length >= Length
               && ((packet[0] << 8) | packet[1]) == HardwareTypeEthernet
               && ((packet[2] << 8) | packet[3]) == ProtocolTypeIpv4
               && packet[4] == HardwareAddressLength
               && packet[5] == ProtocolAddressLength;

        static void WriteIpv4(IPAddress address, Span<byte> destination)
        {
            if (address.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("ARP carries IPv4 addresses only.", nameof(address));
            byte[] bytes = address.GetAddressBytes();   // 4 bytes for IPv4; netstandard2.0 lacks TryWriteBytes
            bytes.CopyTo(destination);
        }
    }
}
