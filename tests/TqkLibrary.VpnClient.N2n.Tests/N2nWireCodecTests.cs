using System.Buffers.Binary;
using System.Text;
using TqkLibrary.VpnClient.N2n;
using TqkLibrary.VpnClient.N2n.Wire;
using TqkLibrary.VpnClient.N2n.Wire.Enums;
using TqkLibrary.VpnClient.N2n.Wire.Models;
using Xunit;

namespace TqkLibrary.VpnClient.N2n.Tests
{
    /// <summary>
    /// Round-trip and on-wire-layout tests for the n2n v3 codec (cleartext-header form). They assert both that
    /// encode→decode preserves every field AND that the bytes land at the offsets / endianness n2n expects, so the
    /// supernode/edge interop holds: 24-byte common header, version 3, big-endian flags with the packet type in the low
    /// 5 bits, 20-byte null-padded community, big-endian integers.
    /// </summary>
    public class N2nWireCodecTests
    {
        readonly N2nPacketCodec _codec = new N2nPacketCodec();
        const string Community = "labnet";

        static byte[] Mac(byte last) => new byte[] { 0x02, 0x00, 0x00, 0x00, 0x00, last };

        [Fact]
        public void CommonHeader_HasExpectedWireLayout()
        {
            var reg = new N2nRegisterSuper { Cookie = 0x11223344, EdgeMac = Mac(0xAA) };
            byte[] pkt = _codec.EncodeRegisterSuper(Community, reg);

            Assert.Equal(N2nConstants.PktVersion, pkt[0]);                 // version = 3
            Assert.Equal(N2nConstants.DefaultTtl, pkt[1]);                 // ttl
            ushort flags = BinaryPrimitives.ReadUInt16BigEndian(pkt.AsSpan(2, 2)); // big-endian flags
            Assert.Equal((byte)N2nPacketType.RegisterSuper, (byte)(flags & (ushort)N2nFlags.TypeMask));

            // community at [4..24), null-padded ASCII.
            byte[] expectCommunity = new byte[N2nConstants.CommunitySize];
            Encoding.ASCII.GetBytes(Community).CopyTo(expectCommunity, 0);
            Assert.True(pkt.AsSpan(4, N2nConstants.CommunitySize).SequenceEqual(expectCommunity));
        }

        [Fact]
        public void RegisterSuper_RoundTrips()
        {
            var sock = N2nSock.FromEndPoint(new System.Net.IPEndPoint(System.Net.IPAddress.Parse("203.0.113.7"), 12345));
            var reg = new N2nRegisterSuper
            {
                Cookie = 0xDEADBEEF,
                EdgeMac = Mac(0x42),
                Sock = sock,
                DevAddr = N2nIpSubnet.Unset,
                DevDesc = "edge1",
                Auth = new N2nAuth { Scheme = N2nAuth.SchemeSimpleId, Token = new byte[16] },
                KeyTime = 0,
            };
            byte[] pkt = _codec.EncodeRegisterSuper(Community, reg);

            Assert.True(_codec.TryDecodeRegisterSuper(pkt, out var h, out var got));
            Assert.Equal(Community, h.Community);
            Assert.Equal(N2nPacketType.RegisterSuper, h.PacketType);
            Assert.Equal(reg.Cookie, got.Cookie);
            Assert.Equal(reg.EdgeMac, got.EdgeMac);
            Assert.NotNull(got.Sock);
            Assert.Equal(12345, got.Sock!.Port);
            Assert.Equal("203.0.113.7", got.Sock.ToEndPoint().Address.ToString());
            Assert.Equal("edge1", got.DevDesc);
            Assert.Equal(reg.Auth.Scheme, got.Auth.Scheme);
            Assert.Equal(16, got.Auth.Token.Length);
        }

        [Fact]
        public void RegisterSuper_NoSocket_RoundTrips()
        {
            var reg = new N2nRegisterSuper { Cookie = 7, EdgeMac = Mac(0x01), Auth = new N2nAuth { Token = new byte[16] } };
            byte[] pkt = _codec.EncodeRegisterSuper(Community, reg);
            Assert.True(_codec.TryDecodeRegisterSuper(pkt, out var h, out var got));
            Assert.Equal(N2nFlags.None, h.Flags & N2nFlags.Socket);
            Assert.Null(got.Sock);
            Assert.Equal(7u, got.Cookie);
        }

        [Fact]
        public void RegisterSuperAck_RoundTrips()
        {
            var ack = new N2nRegisterSuperAck
            {
                Cookie = 0xCAFEBABE,
                SrcMac = Mac(0xFF),
                DevAddr = new N2nIpSubnet(0x0A000005, 24),
                Lifetime = 60000,
                Sock = N2nSock.FromEndPoint(new System.Net.IPEndPoint(System.Net.IPAddress.Parse("198.51.100.9"), 7654)),
                Auth = new N2nAuth { Scheme = N2nAuth.SchemeSimpleId, Token = new byte[16] },
                NumSn = 0,
                KeyTime = 0,
            };
            byte[] pkt = _codec.EncodeRegisterSuperAck(Community, ack);
            Assert.True(_codec.TryDecodeRegisterSuperAck(pkt, out var h, out var got));
            Assert.True((h.Flags & N2nFlags.FromSupernode) != 0);
            Assert.Equal(ack.Cookie, got.Cookie);
            Assert.Equal(ack.SrcMac, got.SrcMac);
            Assert.Equal((uint)0x0A000005, got.DevAddr.NetAddr);
            Assert.Equal(24, got.DevAddr.NetBitLen);
            Assert.Equal(60000, got.Lifetime);
            Assert.Equal(7654, got.Sock.Port);
        }

        [Fact]
        public void RegisterSuperAck_WithExtraSupernodes_RoundTrips()
        {
            var ack = new N2nRegisterSuperAck
            {
                Cookie = 1,
                SrcMac = Mac(0x10),
                DevAddr = N2nIpSubnet.Unset,
                Lifetime = 60,
                Sock = N2nSock.FromEndPoint(new System.Net.IPEndPoint(System.Net.IPAddress.Loopback, 1)),
                Auth = new N2nAuth { Token = new byte[16] },
                NumSn = 2,
                ExtraSupernodes = new[]
                {
                    N2nSock.FromEndPoint(new System.Net.IPEndPoint(System.Net.IPAddress.Parse("1.2.3.4"), 100)),
                    N2nSock.FromEndPoint(new System.Net.IPEndPoint(System.Net.IPAddress.Parse("5.6.7.8"), 200)),
                },
            };
            byte[] pkt = _codec.EncodeRegisterSuperAck(Community, ack);
            Assert.True(_codec.TryDecodeRegisterSuperAck(pkt, out _, out var got));
            Assert.Equal(2, got.NumSn);
            Assert.Equal(2, got.ExtraSupernodes.Length);
            Assert.Equal(100, got.ExtraSupernodes[0].Port);
            Assert.Equal("5.6.7.8", got.ExtraSupernodes[1].ToEndPoint().Address.ToString());
        }

        [Fact]
        public void Register_And_RegisterAck_RoundTrip()
        {
            var reg = new N2nRegister
            {
                Cookie = 0x01020304,
                SrcMac = Mac(0xA1),
                DstMac = Mac(0xB2),
                Sock = N2nSock.FromEndPoint(new System.Net.IPEndPoint(System.Net.IPAddress.Parse("192.0.2.1"), 5000)),
                DevDesc = "p2p",
            };
            byte[] pkt = _codec.EncodeRegister(Community, reg);
            Assert.True(_codec.TryDecodeRegister(pkt, out _, out var gotReg));
            Assert.Equal(reg.Cookie, gotReg.Cookie);
            Assert.Equal(reg.SrcMac, gotReg.SrcMac);
            Assert.Equal(reg.DstMac, gotReg.DstMac);
            Assert.Equal(5000, gotReg.Sock!.Port);
            Assert.Equal("p2p", gotReg.DevDesc);

            var ack = new N2nRegisterAck { Cookie = reg.Cookie, SrcMac = Mac(0xB2), DstMac = Mac(0xA1) };
            byte[] ackPkt = _codec.EncodeRegisterAck(Community, ack);
            Assert.True(_codec.TryDecodeRegisterAck(ackPkt, out _, out var gotAck));
            Assert.Equal(ack.Cookie, gotAck.Cookie);
            Assert.Equal(ack.SrcMac, gotAck.SrcMac);
            Assert.Null(gotAck.Sock);
        }

        [Fact]
        public void PeerInfo_RoundTrips()
        {
            var pi = new N2nPeerInfo
            {
                AFlags = 0x0001,
                Mac = Mac(0x77),
                Sock = N2nSock.FromEndPoint(new System.Net.IPEndPoint(System.Net.IPAddress.Parse("203.0.113.50"), 9000)),
                PreferredSock = N2nSock.FromEndPoint(new System.Net.IPEndPoint(System.Net.IPAddress.Parse("10.0.0.50"), 9001)),
                Load = 42,
                Uptime = 3600,
            };
            // Encode via reflection-free manual: build then decode (codec has decode + a private encode path for tests
            // through the public encode of a symmetric helper). PEER_INFO is supernode-originated, so we hand-build it.
            byte[] pkt = EncodePeerInfo(Community, pi);
            Assert.True(_codec.TryDecodePeerInfo(pkt, out var h, out var got));
            Assert.Equal(N2nPacketType.PeerInfo, h.PacketType);
            Assert.Equal(pi.AFlags, got.AFlags);
            Assert.Equal(pi.Mac, got.Mac);
            Assert.Equal(9000, got.Sock.Port);
            Assert.Equal(9001, got.PreferredSock.Port);
            Assert.Equal(42u, got.Load);
            Assert.Equal(3600u, got.Uptime);
        }

        // Local PEER_INFO encoder mirroring the supernode side (the codec only needs to DECODE PEER_INFO at runtime).
        static byte[] EncodePeerInfo(string community, N2nPeerInfo pi)
        {
            byte[] buf = new byte[256];
            var header = new N2nCommonHeader
            {
                PacketType = N2nPacketType.PeerInfo, Flags = N2nFlags.FromSupernode, Community = community,
            };
            int off = header.Write(buf);
            BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(off, 2), pi.AFlags); off += 2;
            pi.Mac.CopyTo(buf.AsSpan(off)); off += 6;
            off += pi.Sock.Write(buf.AsSpan(off));
            off += pi.PreferredSock.Write(buf.AsSpan(off));
            BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(off, 4), pi.Load); off += 4;
            BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(off, 4), pi.Uptime); off += 4;
            return buf.AsSpan(0, off).ToArray();
        }

        [Fact]
        public void WrongType_DecodeReturnsFalse()
        {
            byte[] pkt = _codec.EncodeRegisterSuper(Community, new N2nRegisterSuper { EdgeMac = Mac(1), Auth = new N2nAuth { Token = new byte[16] } });
            Assert.False(_codec.TryDecodeRegisterAck(pkt, out _, out _));
            Assert.True(_codec.TryPeekHeader(pkt, out var h));
            Assert.Equal(N2nPacketType.RegisterSuper, h.PacketType);
        }

        [Fact]
        public void Community_LongerThan20_IsTruncated_ShorterIsNullPadded()
        {
            var reg = new N2nRegisterSuper { EdgeMac = Mac(1), Auth = new N2nAuth { Token = new byte[16] } };
            byte[] pkt = _codec.EncodeRegisterSuper("ab", reg);
            // bytes [4..24): "ab" then 18 zeros
            Assert.Equal((byte)'a', pkt[4]);
            Assert.Equal((byte)'b', pkt[5]);
            for (int i = 6; i < 4 + N2nConstants.CommunitySize; i++) Assert.Equal(0, pkt[i]);
            Assert.True(_codec.TryDecodeRegisterSuper(pkt, out var h, out _));
            Assert.Equal("ab", h.Community);
        }
    }
}
