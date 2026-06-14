using System.Buffers.Binary;
using TqkLibrary.VpnClient.OpenVpn.Enums;
using TqkLibrary.VpnClient.OpenVpn.Models;

namespace TqkLibrary.VpnClient.OpenVpn
{
    /// <summary>
    /// Encodes/decodes the OpenVPN packet header and control-channel packets (no tls-auth/tls-crypt — those wrap the
    /// control packet and arrive in V2.c). Wire layout of a control packet:
    /// <code>
    ///   opcode|key_id (1) | session_id (8) | ack_len (1) | acked_ids (4·M) | [remote_session_id (8) if M&gt;0]
    ///                     | [packet_id (4) | payload (…) — P_CONTROL/reset only, omitted on P_ACK_V1]
    /// </code>
    /// One UDP datagram is one packet; TCP prefixes each packet with a 16-bit length (handled by the transport).
    /// </summary>
    public static class OpenVpnPacketCodec
    {
        /// <summary>Maximum acknowledgements a single packet can carry (the ack array length is one byte capped here).</summary>
        public const int MaxAcks = 8;

        /// <summary>The opcode in the high 5 bits of a packet's first byte.</summary>
        public static OpenVpnOpcode ReadOpcode(byte first) => (OpenVpnOpcode)(first >> 3);

        /// <summary>The key-id in the low 3 bits of a packet's first byte.</summary>
        public static byte ReadKeyId(byte first) => (byte)(first & 0x07);

        /// <summary>Packs an opcode + key-id into the leading header byte.</summary>
        public static byte Header(OpenVpnOpcode opcode, byte keyId) => (byte)(((byte)opcode << 3) | (keyId & 0x07));

        /// <summary>True for the reliable control-channel opcodes (resets, P_CONTROL, P_ACK, WKC) — not data packets.</summary>
        public static bool IsControlOpcode(OpenVpnOpcode opcode) => opcode switch
        {
            OpenVpnOpcode.ControlHardResetClientV1 => true,
            OpenVpnOpcode.ControlHardResetServerV1 => true,
            OpenVpnOpcode.ControlSoftResetV1 => true,
            OpenVpnOpcode.ControlV1 => true,
            OpenVpnOpcode.AckV1 => true,
            OpenVpnOpcode.ControlHardResetClientV2 => true,
            OpenVpnOpcode.ControlHardResetServerV2 => true,
            OpenVpnOpcode.ControlHardResetClientV3 => true,
            OpenVpnOpcode.ControlWkcV1 => true,
            _ => false,
        };

        /// <summary>Serialises a control packet (or P_ACK_V1) to a single wire datagram.</summary>
        public static byte[] EncodeControl(OpenVpnControlPacket packet)
        {
            int ackCount = Math.Min(packet.AckPacketIds.Count, MaxAcks);
            bool carriesId = !packet.IsAckOnly;

            int length = 1 + 8 + 1 + (ackCount * 4) + (ackCount > 0 ? 8 : 0) + (carriesId ? 4 + packet.Payload.Length : 0);
            byte[] buffer = new byte[length];
            var span = buffer.AsSpan();

            span[0] = Header(packet.Opcode, packet.KeyId);
            BinaryPrimitives.WriteUInt64BigEndian(span.Slice(1, 8), packet.SessionId);
            int offset = 9;

            span[offset++] = (byte)ackCount;
            for (int i = 0; i < ackCount; i++)
            {
                BinaryPrimitives.WriteUInt32BigEndian(span.Slice(offset, 4), packet.AckPacketIds[i]);
                offset += 4;
            }
            if (ackCount > 0)
            {
                BinaryPrimitives.WriteUInt64BigEndian(span.Slice(offset, 8), packet.RemoteSessionId);
                offset += 8;
            }

            if (carriesId)
            {
                BinaryPrimitives.WriteUInt32BigEndian(span.Slice(offset, 4), packet.PacketId);
                offset += 4;
                packet.Payload.CopyTo(span.Slice(offset));
            }
            return buffer;
        }

        /// <summary>Parses a control-channel datagram. Returns false if the opcode is not a control opcode or the bytes are malformed.</summary>
        public static bool TryDecodeControl(ReadOnlySpan<byte> datagram, out OpenVpnControlPacket packet)
        {
            packet = null!;
            if (datagram.Length < 1) return false;

            OpenVpnOpcode opcode = ReadOpcode(datagram[0]);
            if (!IsControlOpcode(opcode)) return false;
            byte keyId = ReadKeyId(datagram[0]);

            if (datagram.Length < 10) return false; // header + session-id + ack-len
            ulong sessionId = BinaryPrimitives.ReadUInt64BigEndian(datagram.Slice(1, 8));
            int offset = 9;

            int ackCount = datagram[offset++];
            if (ackCount > MaxAcks) return false;
            if (datagram.Length < offset + ackCount * 4) return false;
            uint[] acks = ackCount == 0 ? Array.Empty<uint>() : new uint[ackCount];
            for (int i = 0; i < ackCount; i++)
            {
                acks[i] = BinaryPrimitives.ReadUInt32BigEndian(datagram.Slice(offset, 4));
                offset += 4;
            }

            ulong remoteSessionId = 0;
            if (ackCount > 0)
            {
                if (datagram.Length < offset + 8) return false;
                remoteSessionId = BinaryPrimitives.ReadUInt64BigEndian(datagram.Slice(offset, 8));
                offset += 8;
            }

            uint packetId = 0;
            byte[] payload = Array.Empty<byte>();
            if (opcode != OpenVpnOpcode.AckV1)
            {
                if (datagram.Length < offset + 4) return false;
                packetId = BinaryPrimitives.ReadUInt32BigEndian(datagram.Slice(offset, 4));
                offset += 4;
                payload = datagram.Slice(offset).ToArray();
            }

            packet = new OpenVpnControlPacket
            {
                Opcode = opcode,
                KeyId = keyId,
                SessionId = sessionId,
                AckPacketIds = acks,
                RemoteSessionId = remoteSessionId,
                PacketId = packetId,
                Payload = payload,
            };
            return true;
        }
    }
}
