using System.Collections.Generic;
using System.Net;
using TqkLibrary.VpnClient.IpStack;
using TqkLibrary.VpnClient.IpStack.Tcp;
using TqkLibrary.VpnClient.IpStack.Tcp.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.IpStack.Tests
{
    /// <summary>
    /// Codec-level tests for the IPv6 stack: header build/read, extension-header walking, the Fragment extension
    /// header, and the dual-family pseudo-header checksum for TCP/UDP/ICMPv6 over IPv6.
    /// </summary>
    public class Ipv6CodecTests
    {
        static readonly IPAddress Src = IPAddress.Parse("fd00::1");
        static readonly IPAddress Dst = IPAddress.Parse("fd00::2");

        [Fact]
        public void Build_RoundTrips_HeaderFields()
        {
            byte[] payload = { 1, 2, 3, 4, 5 };
            byte[] p = Ipv6.Build(Src, Dst, Ipv6.NextHeaderUdp, payload, hopLimit: 55);

            Assert.Equal(6, Ipv6.Version(p));
            Assert.Equal(payload.Length, Ipv6.PayloadLength(p));
            Assert.Equal(Ipv6.NextHeaderUdp, Ipv6.NextHeader(p));
            Assert.Equal(55, Ipv6.HopLimit(p));
            Assert.Equal(Src, Ipv6.Source(p));
            Assert.Equal(Dst, Ipv6.Destination(p));

            Assert.True(Ipv6.TryGetUpperLayer(p, out byte proto, out int offset));
            Assert.Equal(Ipv6.NextHeaderUdp, proto);
            Assert.Equal(Ipv6.HeaderLength, offset);
            Assert.Equal(payload, p.AsSpan(offset).ToArray());
        }

        [Fact]
        public void TryGetUpperLayer_SkipsHopByHopAndDestinationOptions()
        {
            byte[] udp = { 0xAA, 0xBB, 0xCC, 0xDD };
            var pkt = new List<byte>();
            int payloadLen = 8 + 8 + udp.Length; // Hop-by-Hop(8) + Destination Options(8) + UDP
            pkt.Add(0x60); pkt.Add(0); pkt.Add(0); pkt.Add(0);
            pkt.Add((byte)(payloadLen >> 8)); pkt.Add((byte)payloadLen);
            pkt.Add(Ipv6.NextHeaderHopByHop); // first extension header
            pkt.Add(64);
            pkt.AddRange(Src.GetAddressBytes());
            pkt.AddRange(Dst.GetAddressBytes());
            // Hop-by-Hop: next=DestOptions, hdrExtLen=0 → 8 bytes total (6 pad)
            pkt.Add(Ipv6.NextHeaderDestOptions); pkt.Add(0); for (int i = 0; i < 6; i++) pkt.Add(0);
            // Destination Options: next=UDP, hdrExtLen=0 → 8 bytes (6 pad)
            pkt.Add(Ipv6.NextHeaderUdp); pkt.Add(0); for (int i = 0; i < 6; i++) pkt.Add(0);
            pkt.AddRange(udp);

            byte[] p = pkt.ToArray();
            Assert.True(Ipv6.TryGetUpperLayer(p, out byte proto, out int offset));
            Assert.Equal(Ipv6.NextHeaderUdp, proto);
            Assert.Equal(Ipv6.HeaderLength + 8 + 8, offset);
            Assert.Equal(udp, p.AsSpan(offset).ToArray());
        }

        [Fact]
        public void TryGetUpperLayer_Truncated_ReturnsFalse()
        {
            byte[] p = new byte[Ipv6.HeaderLength];
            p[0] = 0x60;
            p[6] = Ipv6.NextHeaderHopByHop; // claims an extension header that isn't present
            Assert.False(Ipv6.TryGetUpperLayer(p, out _, out _));
        }

        [Fact]
        public void BuildFragment_And_TryGetFragment_RoundTrip()
        {
            byte[] payload = MakePayload(40);
            byte[] frag = Ipv6.BuildFragment(Src, Dst, Ipv6.NextHeaderUdp, payload, identification: 0xDEADBEEF, fragmentOffset: 16, moreFragments: true);

            Assert.Equal(6, Ipv6.Version(frag));
            Assert.Equal(Ipv6.NextHeaderFragment, Ipv6.NextHeader(frag));
            Assert.True(Ipv6.TryGetFragment(frag, out int unfragLen, out int nhField, out byte fragNh, out int offset, out bool more, out uint id));
            Assert.Equal(Ipv6.HeaderLength, unfragLen);
            Assert.Equal(6, nhField); // the fixed header's Next Header byte points to the Fragment header
            Assert.Equal(Ipv6.NextHeaderUdp, fragNh);
            Assert.Equal(16, offset);
            Assert.True(more);
            Assert.Equal(0xDEADBEEFu, id);
            Assert.Equal(payload, frag.AsSpan(Ipv6.HeaderLength + Ipv6.FragmentHeaderLength).ToArray());
        }

        [Fact]
        public void TryGetFragment_WholePacket_ReturnsFalse()
        {
            byte[] whole = Ipv6.Build(Src, Dst, Ipv6.NextHeaderUdp, new byte[] { 1, 2, 3 });
            Assert.False(Ipv6.TryGetFragment(whole, out _, out _, out _, out _, out _, out _));
        }

        [Fact]
        public void TcpSegment_PseudoHeaderChecksum_OverIpv6_Verifies()
        {
            byte[] tcp = TcpSegment.Build(Src, Dst, 1234, 80, 1, 0, TcpFlags.Syn, 65535, ReadOnlySpan<byte>.Empty, mss: 1340);
            Assert.True(VerifyTransportChecksum(Src, Dst, 6, tcp));

            tcp[20] ^= 0xFF; // corrupt an options byte
            Assert.False(VerifyTransportChecksum(Src, Dst, 6, tcp));
        }

        [Fact]
        public void UdpDatagram_PseudoHeaderChecksum_OverIpv6_Verifies()
        {
            byte[] udp = UdpDatagram.Build(Src, Dst, 1234, 53, new byte[] { 1, 2, 3, 4, 5 });
            Assert.True(VerifyTransportChecksum(Src, Dst, 17, udp));

            udp[8] ^= 0xFF; // corrupt a payload byte
            Assert.False(VerifyTransportChecksum(Src, Dst, 17, udp));
        }

        [Fact]
        public void Icmpv6_Echo_RoundTrips_WithChecksum()
        {
            byte[] data = { 0x01, 0x02, 0x03, 0x04, 0x05 };
            byte[] msg = Icmpv6.BuildEcho(Icmpv6.TypeEchoRequest, 0xABCD, 0x0007, data, Src, Dst);

            Assert.Equal(Icmpv6.TypeEchoRequest, Icmpv6.Type(msg));
            Assert.Equal(0, Icmpv6.Code(msg));
            Assert.Equal(0xABCD, Icmpv6.Identifier(msg));
            Assert.Equal(0x0007, Icmpv6.Sequence(msg));
            Assert.Equal(data, Icmpv6.Payload(msg).ToArray());
            Assert.True(Icmpv6.VerifyChecksum(msg, Src, Dst));

            msg[Icmpv6.HeaderSize] ^= 0xFF; // corrupt the payload
            Assert.False(Icmpv6.VerifyChecksum(msg, Src, Dst));
        }

        static bool VerifyTransportChecksum(IPAddress src, IPAddress dst, byte protocol, byte[] segment)
        {
            uint sum = InternetChecksum.PseudoHeaderSum(src, dst, protocol, segment.Length);
            for (int i = 0; i + 1 < segment.Length; i += 2) sum += (uint)((segment[i] << 8) | segment[i + 1]);
            if ((segment.Length & 1) != 0) sum += (uint)(segment[segment.Length - 1] << 8);
            return InternetChecksum.Finish(sum) == 0;
        }

        static byte[] MakePayload(int length)
        {
            byte[] payload = new byte[length];
            for (int i = 0; i < length; i++) payload[i] = (byte)(i * 7 + 1);
            return payload;
        }
    }
}
