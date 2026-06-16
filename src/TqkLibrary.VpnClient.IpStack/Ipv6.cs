using System.Net;

namespace TqkLibrary.VpnClient.IpStack
{
    /// <summary>Builds and reads minimal IPv6 packets (RFC 8200) for the userspace stack, including the Fragment extension header.</summary>
    public static class Ipv6
    {
        /// <summary>Upper-layer protocol number for TCP (shared with IPv4).</summary>
        public const byte NextHeaderTcp = 6;

        /// <summary>Upper-layer protocol number for UDP (shared with IPv4).</summary>
        public const byte NextHeaderUdp = 17;

        /// <summary>Next-header value for ICMPv6 (RFC 4443).</summary>
        public const byte NextHeaderIcmpv6 = 58;

        /// <summary>Next-header value for the Fragment extension header (RFC 8200 §4.5).</summary>
        public const byte NextHeaderFragment = 44;

        /// <summary>Next-header value for the Hop-by-Hop Options extension header.</summary>
        public const byte NextHeaderHopByHop = 0;

        /// <summary>Next-header value for the Routing extension header.</summary>
        public const byte NextHeaderRouting = 43;

        /// <summary>Next-header value for the Destination Options extension header.</summary>
        public const byte NextHeaderDestOptions = 60;

        /// <summary>Next-header value meaning "no next header" (RFC 8200 §4.7).</summary>
        public const byte NextHeaderNone = 59;

        /// <summary>Fixed IPv6 header length in bytes (no extension headers).</summary>
        public const int HeaderLength = 40;

        /// <summary>Length of the Fragment extension header in bytes.</summary>
        public const int FragmentHeaderLength = 8;

        /// <summary>Builds an IPv6 packet (40-byte header, traffic class/flow label 0) wrapping <paramref name="payload"/>.</summary>
        public static byte[] Build(IPAddress source, IPAddress destination, byte nextHeader, ReadOnlySpan<byte> payload, byte hopLimit = 64)
        {
            byte[] packet = new byte[HeaderLength + payload.Length];
            packet[0] = 0x60;                       // Version 6, traffic class high nibble 0
            // bytes 1..4 (traffic class low + flow label) left zero
            packet[4] = (byte)(payload.Length >> 8); // Payload Length
            packet[5] = (byte)payload.Length;
            packet[6] = nextHeader;
            packet[7] = hopLimit;
            source.GetAddressBytes().CopyTo(packet, 8);
            destination.GetAddressBytes().CopyTo(packet, 24);
            payload.CopyTo(packet.AsSpan(HeaderLength));
            return packet;
        }

        /// <summary>
        /// Builds one fragment of an IPv6 datagram: a 40-byte IPv6 header (Next Header = Fragment) followed by an
        /// 8-byte Fragment extension header and the payload fragment (RFC 8200 §4.5). <paramref name="fragmentOffset"/>
        /// is the byte offset within the fragmentable payload (a multiple of 8 except possibly the last fragment);
        /// <paramref name="moreFragments"/> is set on every fragment except the last; all fragments share
        /// <paramref name="identification"/>. <paramref name="upperLayerNextHeader"/> is the protocol of the payload.
        /// </summary>
        public static byte[] BuildFragment(IPAddress source, IPAddress destination, byte upperLayerNextHeader, ReadOnlySpan<byte> payloadFragment, uint identification, int fragmentOffset, bool moreFragments, byte hopLimit = 64)
        {
            byte[] packet = new byte[HeaderLength + FragmentHeaderLength + payloadFragment.Length];
            int payloadLength = FragmentHeaderLength + payloadFragment.Length;
            packet[0] = 0x60;
            packet[4] = (byte)(payloadLength >> 8);
            packet[5] = (byte)payloadLength;
            packet[6] = NextHeaderFragment;
            packet[7] = hopLimit;
            source.GetAddressBytes().CopyTo(packet, 8);
            destination.GetAddressBytes().CopyTo(packet, 24);

            // Fragment extension header at offset 40.
            packet[40] = upperLayerNextHeader;
            packet[41] = 0; // reserved
            int fragField = ((fragmentOffset / 8) << 3) | (moreFragments ? 1 : 0); // offset (13b) | res (2b) | M (1b)
            packet[42] = (byte)(fragField >> 8);
            packet[43] = (byte)fragField;
            packet[44] = (byte)(identification >> 24);
            packet[45] = (byte)(identification >> 16);
            packet[46] = (byte)(identification >> 8);
            packet[47] = (byte)identification;

            payloadFragment.CopyTo(packet.AsSpan(HeaderLength + FragmentHeaderLength));
            return packet;
        }

        /// <summary>
        /// Splits an IPv6 datagram (40-byte header, no preceding extension headers) into fragments each at most
        /// <paramref name="mtu"/> bytes, inserting a Fragment extension header (RFC 8200 §4.5). Returns the datagram
        /// unchanged (single element) if it already fits or cannot be split. The fragmentable payload is cut on 8-byte
        /// boundaries; all fragments share <paramref name="identification"/>.
        /// </summary>
        public static IReadOnlyList<byte[]> Fragment(ReadOnlySpan<byte> datagram, int mtu, uint identification)
        {
            // Largest fragmentable payload per fragment, rounded down to an 8-byte boundary (offset counts 8-byte units).
            int maxPayload = (mtu - HeaderLength - FragmentHeaderLength) & ~7;
            if (datagram.Length <= mtu || datagram.Length < HeaderLength || maxPayload < 8)
                return new[] { datagram.ToArray() };

            byte upperNextHeader = datagram[6];
            IPAddress source = Source(datagram);
            IPAddress destination = Destination(datagram);
            byte hopLimit = datagram[7];
            ReadOnlySpan<byte> payload = datagram.Slice(HeaderLength);

            var fragments = new List<byte[]>();
            for (int offset = 0; offset < payload.Length; offset += maxPayload)
            {
                int length = Math.Min(maxPayload, payload.Length - offset);
                bool moreFragments = offset + length < payload.Length;
                fragments.Add(BuildFragment(source, destination, upperNextHeader, payload.Slice(offset, length), identification, offset, moreFragments, hopLimit));
            }
            return fragments;
        }

        /// <summary>IP version (6 for IPv6).</summary>
        public static byte Version(ReadOnlySpan<byte> packet) => (byte)(packet[0] >> 4);

        /// <summary>Payload length in bytes (everything after the 40-byte header, including extension headers).</summary>
        public static int PayloadLength(ReadOnlySpan<byte> packet) => (packet[4] << 8) | packet[5];

        /// <summary>The Next Header field of the fixed header.</summary>
        public static byte NextHeader(ReadOnlySpan<byte> packet) => packet[6];

        /// <summary>The Hop Limit field.</summary>
        public static byte HopLimit(ReadOnlySpan<byte> packet) => packet[7];

        /// <summary>The source address.</summary>
        public static IPAddress Source(ReadOnlySpan<byte> packet) => new IPAddress(packet.Slice(8, 16).ToArray());

        /// <summary>The destination address.</summary>
        public static IPAddress Destination(ReadOnlySpan<byte> packet) => new IPAddress(packet.Slice(24, 16).ToArray());

        /// <summary>
        /// Walks the extension-header chain from the fixed header to the upper-layer protocol, skipping Hop-by-Hop,
        /// Routing, Destination Options and (defensively) Fragment headers. Returns false if the chain is malformed,
        /// truncated, or ends in "no next header". On success, <paramref name="protocol"/> is the upper-layer
        /// next-header value and <paramref name="payloadOffset"/> is the byte offset where its payload begins.
        /// </summary>
        public static bool TryGetUpperLayer(ReadOnlySpan<byte> packet, out byte protocol, out int payloadOffset)
        {
            protocol = 0;
            payloadOffset = 0;
            if (packet.Length < HeaderLength) return false;

            byte next = packet[6];
            int pos = HeaderLength;
            while (true)
            {
                switch (next)
                {
                    case NextHeaderHopByHop:
                    case NextHeaderRouting:
                    case NextHeaderDestOptions:
                    {
                        if (pos + 2 > packet.Length) return false;
                        byte following = packet[pos];
                        int extLen = (packet[pos + 1] + 1) * 8; // length in 8-byte units, not counting the first 8 bytes
                        if (pos + extLen > packet.Length) return false;
                        next = following;
                        pos += extLen;
                        break;
                    }
                    case NextHeaderFragment:
                    {
                        if (pos + FragmentHeaderLength > packet.Length) return false;
                        next = packet[pos];
                        pos += FragmentHeaderLength;
                        break;
                    }
                    case NextHeaderNone:
                        return false;
                    default:
                        protocol = next;
                        payloadOffset = pos;
                        return true;
                }
            }
        }

        /// <summary>
        /// Parses the Fragment extension header if present (RFC 8200 §4.5), walking any Hop-by-Hop/Routing/Destination
        /// Options headers that precede it. Returns false if the packet carries no Fragment header (a whole datagram) or
        /// is malformed. On success: <paramref name="unfragmentableLength"/> is the byte length of the part before the
        /// Fragment header; <paramref name="nextHeaderFieldOffset"/> is the offset of the Next Header byte that points to
        /// the Fragment header (so reassembly can unlink it); <paramref name="fragmentNextHeader"/> is the first header of
        /// the fragmentable part; offset/M/identification describe this fragment.
        /// </summary>
        public static bool TryGetFragment(ReadOnlySpan<byte> packet, out int unfragmentableLength, out int nextHeaderFieldOffset, out byte fragmentNextHeader, out int fragmentOffset, out bool moreFragments, out uint identification)
        {
            unfragmentableLength = 0;
            nextHeaderFieldOffset = 6;
            fragmentNextHeader = 0;
            fragmentOffset = 0;
            moreFragments = false;
            identification = 0;
            if (packet.Length < HeaderLength) return false;

            byte next = packet[6];
            int nextField = 6;
            int pos = HeaderLength;
            while (true)
            {
                if (next == NextHeaderFragment)
                {
                    if (pos + FragmentHeaderLength > packet.Length) return false;
                    unfragmentableLength = pos;
                    nextHeaderFieldOffset = nextField;
                    fragmentNextHeader = packet[pos];
                    int fragField = (packet[pos + 2] << 8) | packet[pos + 3];
                    fragmentOffset = (fragField >> 3) * 8;
                    moreFragments = (fragField & 1) != 0;
                    identification = ((uint)packet[pos + 4] << 24) | ((uint)packet[pos + 5] << 16) | ((uint)packet[pos + 6] << 8) | packet[pos + 7];
                    return true;
                }
                if (next == NextHeaderHopByHop || next == NextHeaderRouting || next == NextHeaderDestOptions)
                {
                    if (pos + 2 > packet.Length) return false;
                    byte following = packet[pos];
                    int extLen = (packet[pos + 1] + 1) * 8;
                    if (pos + extLen > packet.Length) return false;
                    nextField = pos;
                    next = following;
                    pos += extLen;
                    continue;
                }
                return false; // reached an upper-layer protocol without a Fragment header
            }
        }
    }
}
