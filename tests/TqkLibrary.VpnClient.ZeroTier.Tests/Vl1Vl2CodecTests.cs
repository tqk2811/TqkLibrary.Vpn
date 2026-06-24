using System.Net;
using TqkLibrary.VpnClient.ZeroTier.Identity.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl1;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl2;
using TqkLibrary.VpnClient.ZeroTier.Vl2.Models;
using Xunit;

namespace TqkLibrary.VpnClient.ZeroTier.Tests
{
    /// <summary>
    /// Offline round-trip + layout tests for the VL1/VL2 codecs the driver runtime adds: the InetAddress serializer, the
    /// OK(HELLO) parser, the ZeroTier dictionary, the network-config decode, and the EXT_FRAME codec. The exact byte
    /// offsets are clean-room from the public ZeroTier wire description (verbs / dictionary keys); live validation against
    /// a real node is the driver's job.
    /// </summary>
    public class Vl1Vl2CodecTests
    {
        [Fact]
        public void InetAddress_Ipv4_RoundTrips()
        {
            var codec = new InetAddressCodec();
            var value = new InetAddressValue { Address = IPAddress.Parse("10.7.0.2"), Port = 24 };
            byte[] wire = codec.Encode(value);
            Assert.Equal(7, wire.Length);       // tag + 4 + 2
            Assert.Equal(0x04, wire[0]);
            Assert.True(codec.TryDecode(wire, out var parsed, out int consumed));
            Assert.Equal(7, consumed);
            Assert.Equal(value.Address, parsed.Address);
            Assert.Equal(24, parsed.Port);
        }

        [Fact]
        public void InetAddress_Nil_IsSingleZeroByte()
        {
            var codec = new InetAddressCodec();
            byte[] wire = codec.Encode(InetAddressValue.Nil);
            Assert.Equal(new byte[] { 0x00 }, wire);
            Assert.True(codec.TryDecode(wire, out var parsed, out int consumed));
            Assert.Equal(1, consumed);
            Assert.True(parsed.IsNil);
        }

        [Fact]
        public void Dictionary_RoundTrips_EscapingBinaryValues()
        {
            var dict = new ZeroTierDictionary();
            dict.SetString("n", "labnet");
            dict.SetUInt64("mtu", 2800);
            dict.SetBytes("C", new byte[] { 0x00, (byte)'=', (byte)'\n', 0xFF, (byte)'\\' }); // every escape case

            byte[] wire = dict.Serialize();
            var back = ZeroTierDictionary.Deserialize(wire);
            Assert.Equal("labnet", back.GetString("n"));
            Assert.True(back.TryGetUInt64("mtu", out ulong mtu));
            Assert.Equal(2800UL, mtu);
            Assert.Equal(new byte[] { 0x00, (byte)'=', (byte)'\n', 0xFF, (byte)'\\' }, back.GetBytes("C"));
        }

        [Fact]
        public void NetworkConfig_Decodes_AssignedIp_And_Com_FromDictionary()
        {
            // Build a controller-style config dictionary: one assigned /24 IPv4 + a COM blob, wrapped as
            // networkId(8) || dictLen(2 BE) || dict (the body the driver decodes after the OK common header).
            var inet = new InetAddressCodec();
            byte[] ipBlob = inet.Encode(new InetAddressValue { Address = IPAddress.Parse("10.7.0.2"), Port = 24 });
            byte[] com = new byte[1 + 2 + 5 + 64]; // version + qualifierCount(0) + signedBy + signature
            com[0] = 1;

            var dict = new ZeroTierDictionary();
            dict.SetBytes("I", ipBlob);
            dict.SetBytes("C", com);
            dict.SetUInt64("mtu", 2800);
            byte[] dictBytes = dict.Serialize();

            var nwid = NetworkId.Parse("8056c2e21c000001");
            byte[] body = new byte[8 + 2 + dictBytes.Length];
            nwid.Write(body.AsSpan(0, 8));
            body[8] = (byte)(dictBytes.Length >> 8);
            body[9] = (byte)dictBytes.Length;
            dictBytes.CopyTo(body, 10);

            var codec = new NetworkConfigCodec();
            Assert.True(codec.TryDecodeConfig(body, out var config));
            Assert.Equal(nwid, config.Network);
            Assert.True(config.HasAssignedAddress);
            Assert.Equal(IPAddress.Parse("10.7.0.2"), config.AssignedAddresses[0].Address);
            Assert.Equal(24, config.AssignedAddresses[0].Port);   // prefix carried in the port field
            Assert.Equal(2800, config.Mtu);
            Assert.NotNull(config.CertificateOfMembership);
            Assert.Equal(com, config.CertificateOfMembership);
        }

        [Fact]
        public void NetworkConfigRequest_Encodes_NetworkId_And_DictLength()
        {
            var codec = new NetworkConfigCodec();
            var nwid = NetworkId.Parse("8056c2e21c000001");
            byte[] body = codec.EncodeRequest(nwid);
            Assert.Equal(nwid, NetworkId.Read(body.AsSpan(0, 8)));
            int dictLen = (body[8] << 8) | body[9];
            Assert.Equal(body.Length - 10, dictLen);  // dictLen covers exactly the trailing dictionary
        }

        [Fact]
        public void OkHello_Parses_TimestampEcho_And_PhysicalDestination()
        {
            // Build an OK(HELLO) body: common(inReVerb=HELLO, inRePacketId) || timestamp || versions || physical InetAddr.
            var inet = new InetAddressCodec();
            byte[] physical = inet.Encode(new InetAddressValue { Address = IPAddress.Parse("203.0.113.5"), Port = 12345 });
            byte[] body = new byte[1 + 8 + 8 + 1 + 1 + 1 + 2 + physical.Length];
            int o = 0;
            body[o++] = 0x01;                                                  // in-re-verb = HELLO
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(o, 8), 0xAABBCCDDUL); o += 8;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(o, 8), 0x1122334455UL); o += 8; // timestamp
            body[o++] = 13; body[o++] = 1; body[o++] = 14;                      // proto / major / minor
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(o, 2), 0); o += 2; // revision
            physical.CopyTo(body, o);

            var codec = new OkMessageCodec();
            Assert.True(codec.TryDecodeCommon(body, out byte inReVerb, out ulong inRePacketId));
            Assert.Equal(0x01, inReVerb);
            Assert.Equal(0xAABBCCDDUL, inRePacketId);

            Assert.True(codec.TryDecodeOkHello(body, out var ok));
            Assert.Equal(0x1122334455UL, ok.TimestampEcho);
            Assert.Equal(13, ok.ProtocolVersion);
            Assert.Equal(IPAddress.Parse("203.0.113.5"), ok.PhysicalDestination.Address);
            Assert.Equal(12345, ok.PhysicalDestination.Port);
        }

        [Fact]
        public void ExtFrame_RoundTrips_WithAndWithoutCom()
        {
            var codec = new Vl2ExtFrameCodec();
            var nwid = NetworkId.Parse("8056c2e21c000001");
            byte[] com = new byte[1 + 2 + 5 + 64]; com[0] = 1; // qualifierCount 0 -> fixed size

            var withCom = new Vl2ExtFrame
            {
                Network = nwid,
                Flags = Vl2ExtFrame.FlagComAttached,
                CertificateOfMembership = com,
                DestinationMac = new byte[] { 1, 2, 3, 4, 5, 6 },
                SourceMac = new byte[] { 7, 8, 9, 10, 11, 12 },
                EtherType = 0x0800,
                FrameData = new byte[] { 0x45, 0x00, 0xDE, 0xAD },
            };
            byte[] wire = codec.Encode(withCom);
            Assert.True(codec.TryDecode(wire, out var back));
            Assert.Equal(nwid, back.Network);
            Assert.Equal(com, back.CertificateOfMembership);
            Assert.Equal(withCom.DestinationMac, back.DestinationMac);
            Assert.Equal(withCom.SourceMac, back.SourceMac);
            Assert.Equal(0x0800, back.EtherType);
            Assert.Equal(withCom.FrameData, back.FrameData);

            var noCom = new Vl2ExtFrame
            {
                Network = nwid,
                Flags = 0,
                DestinationMac = new byte[] { 1, 2, 3, 4, 5, 6 },
                SourceMac = new byte[] { 7, 8, 9, 10, 11, 12 },
                EtherType = 0x0806,
                FrameData = new byte[] { 0xAA, 0xBB },
            };
            byte[] wire2 = codec.Encode(noCom);
            Assert.True(codec.TryDecode(wire2, out var back2));
            Assert.Null(back2.CertificateOfMembership);
            Assert.Equal(0x0806, back2.EtherType);
            Assert.Equal(noCom.FrameData, back2.FrameData);
        }
    }
}
