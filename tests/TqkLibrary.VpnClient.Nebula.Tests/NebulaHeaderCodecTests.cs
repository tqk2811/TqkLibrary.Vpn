using TqkLibrary.VpnClient.Nebula.Packet;
using TqkLibrary.VpnClient.Nebula.Packet.Enums;
using TqkLibrary.VpnClient.Nebula.Packet.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Nebula.Tests
{
    public class NebulaHeaderCodecTests
    {
        readonly NebulaHeaderCodec _codec = new();

        [Fact]
        public void Header_RoundTrips()
        {
            var header = new NebulaHeader
            {
                Version = 1,
                Type = NebulaMessageType.Message,
                SubType = (byte)NebulaMessageSubType.None,
                Reserved = 0,
                RemoteIndex = 0xDEADBEEF,
                MessageCounter = 0x0102030405060708UL,
            };

            byte[] bytes = _codec.Encode(header);
            Assert.Equal(16, bytes.Length);

            Assert.True(_codec.TryDecode(bytes, out NebulaHeader back));
            Assert.Equal(1, back.Version);
            Assert.Equal(NebulaMessageType.Message, back.Type);
            Assert.Equal(0, back.SubType);
            Assert.Equal(0xDEADBEEFu, back.RemoteIndex);
            Assert.Equal(0x0102030405060708UL, back.MessageCounter);
        }

        [Fact]
        public void Header_ByteLayout_IsBigEndianAndPacked()
        {
            var header = new NebulaHeader
            {
                Version = 1,
                Type = NebulaMessageType.Handshake, // 0
                SubType = 0,
                RemoteIndex = 0x00000001,
                MessageCounter = 0x00000000000000FFUL,
            };
            byte[] b = _codec.Encode(header);

            // byte0 = version<<4 | type = 0x10
            Assert.Equal(0x10, b[0]);
            Assert.Equal(0x00, b[1]);                      // subtype
            Assert.Equal(0x00, b[2]); Assert.Equal(0x00, b[3]); // reserved
            // RemoteIndex big-endian
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x01 }, b[4..8]);
            // MessageCounter big-endian
            Assert.Equal(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0xFF }, b[8..16]);
        }

        [Fact]
        public void Header_VersionAndTypeNibbles_DecodeIndependently()
        {
            // 0x16 => version 1, type 6 (Control)
            byte[] raw = new byte[16];
            raw[0] = 0x16;
            Assert.True(_codec.TryDecode(raw, out NebulaHeader h));
            Assert.Equal(1, h.Version);
            Assert.Equal(NebulaMessageType.Control, h.Type);
        }

        [Fact]
        public void EncodePacket_PrependsHeader()
        {
            var header = new NebulaHeader { Type = NebulaMessageType.Handshake };
            byte[] payload = { 0xAA, 0xBB, 0xCC };
            byte[] packet = _codec.EncodePacket(header, payload);
            Assert.Equal(19, packet.Length);
            Assert.Equal(payload, packet[16..]);
        }

        [Fact]
        public void TryDecode_TooShort_ReturnsFalse()
        {
            Assert.False(_codec.TryDecode(new byte[15], out _));
        }
    }
}
