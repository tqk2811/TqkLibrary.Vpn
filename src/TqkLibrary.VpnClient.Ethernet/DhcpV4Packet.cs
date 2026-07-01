using System;
using System.Net;
using TqkLibrary.VpnClient.Abstractions.Net;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// Builds and reads the DHCP/BOOTP message (RFC 2131 §2): a fixed 236-byte header (op/htype/hlen/hops, xid, secs,
    /// flags, ciaddr/yiaddr/siaddr/giaddr, 16-byte chaddr, 64-byte sname, 128-byte file) followed by the option field
    /// (magic cookie + TLV, see <see cref="DhcpV4Options"/>). It also wraps a built DHCP message in a UDP/IPv4 packet
    /// (client port 68 → server port 67) and reads one back, so the configurator can pump it through an
    /// <see cref="IEthernetChannel"/> exactly like ARP/NDISC ride on top of the codec — the L2 layer never references
    /// the L3 <c>IpStack</c> project (it builds the IPv4 + UDP bytes itself, like <see cref="Icmpv6Ndisc"/> does for v6).
    /// <para>
    /// Mirrors the static, allocation-light codec style of <see cref="ArpPacket"/> / <see cref="Icmpv6Ndisc"/>.
    /// </para>
    /// </summary>
    public static class DhcpV4Packet
    {
        /// <summary>BOOTP op code: a request from client to server (RFC 2131 §2).</summary>
        public const byte OpBootRequest = 1;

        /// <summary>BOOTP op code: a reply from server to client (RFC 2131 §2).</summary>
        public const byte OpBootReply = 2;

        /// <summary>Hardware type for 10 Mb Ethernet (RFC 2131 §2 / RFC 1700) — htype 1.</summary>
        public const byte HardwareTypeEthernet = 1;

        /// <summary>Hardware address length for Ethernet (6 octets).</summary>
        public const byte HardwareAddressLength = 6;

        /// <summary>The Broadcast flag (RFC 2131 §4.1, high bit of the 16-bit flags field).</summary>
        public const ushort FlagBroadcast = 0x8000;

        /// <summary>Length of the fixed BOOTP header before the option field (op … 128-byte file).</summary>
        public const int HeaderLength = 236;

        /// <summary>UDP port a DHCP client receives on (RFC 2131 §4.1) — also the source port of client messages.</summary>
        public const ushort ClientPort = 68;

        /// <summary>UDP port a DHCP server listens on (RFC 2131 §4.1) — the destination port of client messages.</summary>
        public const ushort ServerPort = 67;

        const int Ipv4HeaderLength = 20;
        const int UdpHeaderLength = 8;

        const int OffsetXid = 4;
        const int OffsetSecs = 8;
        const int OffsetFlags = 10;
        const int OffsetCiaddr = 12;
        const int OffsetYiaddr = 16;
        const int OffsetSiaddr = 20;
        const int OffsetGiaddr = 24;
        const int OffsetChaddr = 28;

        /// <summary>
        /// Builds a DHCP/BOOTP message: the 236-byte header carrying <paramref name="xid"/> + the client MAC in
        /// <c>chaddr</c>, then the magic cookie and <paramref name="options"/> appended after it (the caller writes the
        /// options starting with <see cref="DhcpV4Options.WriteMagicCookie"/>). When <paramref name="broadcast"/> is set
        /// the Broadcast flag is raised so the server replies to the broadcast address (we have no IP yet).
        /// </summary>
        public static byte[] Build(uint xid, MacAddress clientMac, IPAddress? requestedCiaddr, bool broadcast, ReadOnlySpan<byte> optionField)
        {
            byte[] message = new byte[HeaderLength + optionField.Length];
            message[0] = OpBootRequest;
            message[1] = HardwareTypeEthernet;
            message[2] = HardwareAddressLength;
            // hops (3) = 0
            WriteUInt32(message, OffsetXid, xid);
            // secs (8..10) = 0
            if (broadcast)
            {
                message[OffsetFlags] = (byte)(FlagBroadcast >> 8);
                message[OffsetFlags + 1] = (byte)(FlagBroadcast & 0xFF);
            }
            if (requestedCiaddr != null)
                requestedCiaddr.GetAddressBytes().CopyTo(message, OffsetCiaddr);
            // yiaddr/siaddr/giaddr left zero
            clientMac.CopyTo(message.AsSpan(OffsetChaddr, MacAddress.Size));   // chaddr (16 bytes; rest zero pad)
            // sname (64) + file (128) left zero
            optionField.CopyTo(message.AsSpan(HeaderLength));
            return message;
        }

        /// <summary>True if <paramref name="message"/> is a BOOTREPLY whose <c>xid</c> matches and whose option field carries the magic cookie.</summary>
        public static bool IsReplyFor(ReadOnlySpan<byte> message, uint xid)
            => message.Length >= HeaderLength + 4
               && message[0] == OpBootReply
               && Xid(message) == xid
               && DhcpV4Options.HasMagicCookie(message.Slice(HeaderLength));

        /// <summary>The transaction id (RFC 2131 §3, 32-bit xid at offset 4).</summary>
        public static uint Xid(ReadOnlySpan<byte> message) => ReadUInt32(message, OffsetXid);

        /// <summary>The "your IP address" (<c>yiaddr</c>) the server is offering/assigning (offset 16).</summary>
        public static IPAddress YourIpAddress(ReadOnlySpan<byte> message) => ReadAddress(message, OffsetYiaddr);

        /// <summary>The "server IP address" (<c>siaddr</c>) the server filled in (offset 20).</summary>
        public static IPAddress ServerIpAddress(ReadOnlySpan<byte> message) => ReadAddress(message, OffsetSiaddr);

        /// <summary>The relay/gateway IP (<c>giaddr</c>, offset 24) — zero for a direct exchange.</summary>
        public static IPAddress GatewayIpAddress(ReadOnlySpan<byte> message) => ReadAddress(message, OffsetGiaddr);

        /// <summary>The option field (after the 236-byte header), beginning with the magic cookie.</summary>
        public static ReadOnlyMemory<byte> OptionField(ReadOnlyMemory<byte> message) => message.Slice(HeaderLength);

        // ---- UDP/IPv4 framing (so DHCP can ride an IEthernetChannel without referencing the IpStack project) ----

        /// <summary>
        /// Wraps a built DHCP <paramref name="dhcpMessage"/> in a UDP/IPv4 packet from <paramref name="source"/>:68 to
        /// <paramref name="destination"/>:67 (RFC 2131 §4.1). For DISCOVER/REQUEST the source is <c>0.0.0.0</c> and the
        /// destination <c>255.255.255.255</c>. The IPv4 header checksum and the UDP checksum (with pseudo-header) are
        /// computed here; a zero UDP checksum (legal for IPv4) is left as the computed value.
        /// </summary>
        public static byte[] BuildUdpIpv4(IPAddress source, IPAddress destination, ushort sourcePort, ushort destinationPort, ReadOnlySpan<byte> dhcpMessage)
        {
            int udpLength = UdpHeaderLength + dhcpMessage.Length;
            int totalLength = Ipv4HeaderLength + udpLength;
            byte[] packet = new byte[totalLength];

            // IPv4 header (RFC 791)
            packet[0] = 0x45;                                   // version 4, IHL 5 (no options)
            // DSCP/ECN (1) = 0
            packet[2] = (byte)(totalLength >> 8);
            packet[3] = (byte)totalLength;
            // identification (4..6) = 0, flags/fragment (6..8) = 0
            packet[8] = 64;                                     // TTL
            packet[9] = 17;                                     // protocol = UDP
            // header checksum (10..12) computed below
            source.GetAddressBytes().CopyTo(packet, 12);
            destination.GetAddressBytes().CopyTo(packet, 16);
            ushort ipChecksum = InternetChecksum.Compute(packet.AsSpan(0, Ipv4HeaderLength));
            packet[10] = (byte)(ipChecksum >> 8);
            packet[11] = (byte)ipChecksum;

            // UDP header (RFC 768)
            int udp = Ipv4HeaderLength;
            packet[udp] = (byte)(sourcePort >> 8);
            packet[udp + 1] = (byte)sourcePort;
            packet[udp + 2] = (byte)(destinationPort >> 8);
            packet[udp + 3] = (byte)destinationPort;
            packet[udp + 4] = (byte)(udpLength >> 8);
            packet[udp + 5] = (byte)udpLength;
            // checksum (udp+6 .. udp+8) computed below
            dhcpMessage.CopyTo(packet.AsSpan(udp + UdpHeaderLength));
            ushort udpChecksum = UdpChecksum(source, destination, packet.AsSpan(udp, udpLength));
            packet[udp + 6] = (byte)(udpChecksum >> 8);
            packet[udp + 7] = (byte)udpChecksum;
            return packet;
        }

        /// <summary>
        /// Extracts the DHCP message from a UDP/IPv4 packet if it is a well-formed IPv4/UDP datagram destined for the
        /// DHCP client port (68); returns <c>false</c> otherwise (slices without copying). Verifies neither checksum
        /// (the server replies are trusted on this point-to-point/in-memory fabric, matching the rest of the L2 layer).
        /// </summary>
        public static bool TryReadUdpIpv4(ReadOnlyMemory<byte> packet, out ReadOnlyMemory<byte> dhcpMessage)
        {
            dhcpMessage = default;
            ReadOnlySpan<byte> span = packet.Span;
            if (span.Length < Ipv4HeaderLength + UdpHeaderLength)
                return false;
            if ((byte)(span[0] >> 4) != 4)
                return false;                                   // not IPv4
            int ihl = (span[0] & 0x0F) * 4;
            if (ihl < Ipv4HeaderLength || span.Length < ihl + UdpHeaderLength)
                return false;
            if (span[9] != 17)
                return false;                                   // not UDP
            int udp = ihl;
            int destPort = (span[udp + 2] << 8) | span[udp + 3];
            if (destPort != ClientPort)
                return false;                                   // not addressed to the DHCP client port
            int udpLength = (span[udp + 4] << 8) | span[udp + 5];
            if (udpLength < UdpHeaderLength || udp + udpLength > span.Length)
                return false;
            dhcpMessage = packet.Slice(udp + UdpHeaderLength, udpLength - UdpHeaderLength);
            return true;
        }

        // ---- Internals ----

        static IPAddress ReadAddress(ReadOnlySpan<byte> message, int offset)
            => new IPAddress(message.Slice(offset, 4).ToArray());

        static ushort UdpChecksum(IPAddress source, IPAddress destination, ReadOnlySpan<byte> udpDatagram)
        {
            // IPv4 UDP pseudo-header (RFC 768): src(4) + dst(4) + zero(1) + protocol(1) + UDP length(2), then the datagram.
            uint sum = InternetChecksum.PseudoHeaderSum(source, destination, 17 /* UDP */, udpDatagram.Length);
            sum = InternetChecksum.AddData(sum, udpDatagram);
            ushort folded = InternetChecksum.Finish(sum);
            return folded == 0 ? (ushort)0xFFFF : folded;       // RFC 768: a computed 0 is transmitted as all-ones
        }

        static uint ReadUInt32(ReadOnlySpan<byte> b, int offset)
            => ((uint)b[offset] << 24) | ((uint)b[offset + 1] << 16) | ((uint)b[offset + 2] << 8) | b[offset + 3];

        static void WriteUInt32(byte[] b, int offset, uint value)
        {
            b[offset] = (byte)(value >> 24);
            b[offset + 1] = (byte)(value >> 16);
            b[offset + 2] = (byte)(value >> 8);
            b[offset + 3] = (byte)value;
        }
    }
}
