using TqkLibrary.VpnClient.OpenVpn;
using TqkLibrary.VpnClient.OpenVpn.Enums;
using TqkLibrary.VpnClient.OpenVpn.Models;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>Wire-format checks for the OpenVPN control-packet codec (opcode/key-id packing + round trips).</summary>
    public class OpenVpnPacketCodecTests
    {
        [Theory]
        [InlineData(OpenVpnOpcode.ControlV1, 0)]
        [InlineData(OpenVpnOpcode.ControlHardResetClientV2, 7)]
        [InlineData(OpenVpnOpcode.AckV1, 3)]
        public void Header_PacksOpcodeHigh5AndKeyIdLow3(OpenVpnOpcode opcode, byte keyId)
        {
            byte header = OpenVpnPacketCodec.Header(opcode, keyId);

            Assert.Equal(opcode, OpenVpnPacketCodec.ReadOpcode(header));
            Assert.Equal(keyId, OpenVpnPacketCodec.ReadKeyId(header));
            Assert.Equal((byte)(((byte)opcode << 3) | keyId), header);
        }

        [Fact]
        public void ControlV1_WithAcksAndPayload_RoundTrips()
        {
            var packet = new OpenVpnControlPacket
            {
                Opcode = OpenVpnOpcode.ControlV1,
                KeyId = 2,
                SessionId = 0x0102030405060708UL,
                AckPacketIds = new uint[] { 5, 6, 7 },
                RemoteSessionId = 0xAABBCCDDEEFF0011UL,
                PacketId = 42,
                Payload = new byte[] { 0x16, 0x03, 0x01, 0xDE, 0xAD },
            };

            byte[] wire = OpenVpnPacketCodec.EncodeControl(packet);
            // 1 header + 8 session + 1 ack-len + 3*4 acks + 8 remote-session + 4 packet-id + 5 payload = 39
            Assert.Equal(39, wire.Length);

            Assert.True(OpenVpnPacketCodec.TryDecodeControl(wire, out OpenVpnControlPacket decoded));
            Assert.Equal(OpenVpnOpcode.ControlV1, decoded.Opcode);
            Assert.Equal((byte)2, decoded.KeyId);
            Assert.Equal(packet.SessionId, decoded.SessionId);
            Assert.Equal(new uint[] { 5, 6, 7 }, decoded.AckPacketIds);
            Assert.Equal(packet.RemoteSessionId, decoded.RemoteSessionId);
            Assert.Equal(42u, decoded.PacketId);
            Assert.Equal(packet.Payload, decoded.Payload);
        }

        [Fact]
        public void HardResetClientV2_NoAcksEmptyPayload_RoundTrips()
        {
            var packet = new OpenVpnControlPacket
            {
                Opcode = OpenVpnOpcode.ControlHardResetClientV2,
                KeyId = 0,
                SessionId = 0x1122334455667788UL,
                PacketId = 0,
            };

            byte[] wire = OpenVpnPacketCodec.EncodeControl(packet);
            // 1 header + 8 session + 1 ack-len(0) + 0 acks + no remote-session + 4 packet-id + 0 payload = 14
            Assert.Equal(14, wire.Length);

            Assert.True(OpenVpnPacketCodec.TryDecodeControl(wire, out OpenVpnControlPacket decoded));
            Assert.Equal(OpenVpnOpcode.ControlHardResetClientV2, decoded.Opcode);
            Assert.Equal(packet.SessionId, decoded.SessionId);
            Assert.Empty(decoded.AckPacketIds);
            Assert.Equal(0u, decoded.PacketId);
            Assert.Empty(decoded.Payload);
        }

        [Fact]
        public void AckV1_CarriesAcksOnly_NoPacketIdNoPayload()
        {
            var packet = new OpenVpnControlPacket
            {
                Opcode = OpenVpnOpcode.AckV1,
                SessionId = 0xDEADBEEFCAFEBABEUL,
                AckPacketIds = new uint[] { 0 },
                RemoteSessionId = 0x0011223344556677UL,
                PacketId = 999,                 // must be ignored on the wire for P_ACK
                Payload = new byte[] { 1, 2, 3 } // must be ignored on the wire for P_ACK
            };

            byte[] wire = OpenVpnPacketCodec.EncodeControl(packet);
            // 1 header + 8 session + 1 ack-len + 4 ack + 8 remote-session = 22 (no packet-id, no payload)
            Assert.Equal(22, wire.Length);

            Assert.True(OpenVpnPacketCodec.TryDecodeControl(wire, out OpenVpnControlPacket decoded));
            Assert.True(decoded.IsAckOnly);
            Assert.Equal(new uint[] { 0 }, decoded.AckPacketIds);
            Assert.Equal(packet.RemoteSessionId, decoded.RemoteSessionId);
            Assert.Equal(0u, decoded.PacketId);
            Assert.Empty(decoded.Payload);
        }

        [Fact]
        public void Decode_RejectsDataOpcodeAndTruncatedBytes()
        {
            // P_DATA_V1 is not a control packet.
            byte dataHeader = OpenVpnPacketCodec.Header(OpenVpnOpcode.DataV1, 0);
            Assert.False(OpenVpnPacketCodec.TryDecodeControl(new byte[] { dataHeader, 1, 2, 3 }, out _));

            // A control header that ends before the session-id / ack array is complete.
            byte ctrlHeader = OpenVpnPacketCodec.Header(OpenVpnOpcode.ControlV1, 0);
            Assert.False(OpenVpnPacketCodec.TryDecodeControl(new byte[] { ctrlHeader, 0, 0, 0 }, out _));

            // Empty input.
            Assert.False(OpenVpnPacketCodec.TryDecodeControl(ReadOnlySpan<byte>.Empty, out _));
        }

        [Fact]
        public void Decode_RejectsAckCountBeyondMax()
        {
            byte ctrlHeader = OpenVpnPacketCodec.Header(OpenVpnOpcode.ControlV1, 0);
            byte[] wire = new byte[1 + 8 + 1];
            wire[0] = ctrlHeader;
            wire[9] = (byte)(OpenVpnPacketCodec.MaxAcks + 1); // claims more acks than allowed

            Assert.False(OpenVpnPacketCodec.TryDecodeControl(wire, out _));
        }
    }
}
