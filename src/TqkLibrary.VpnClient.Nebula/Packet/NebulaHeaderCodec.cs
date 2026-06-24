using System.Buffers.Binary;
using TqkLibrary.VpnClient.Nebula.Packet.Enums;
using TqkLibrary.VpnClient.Nebula.Packet.Models;

namespace TqkLibrary.VpnClient.Nebula.Packet
{
    /// <summary>
    /// Encodes and decodes the 16-byte Nebula packet header (big-endian) and frames a payload behind it. The header
    /// of a data packet is also the AEAD associated data, so <see cref="Encode"/> writes exactly the 16 bytes the
    /// peer authenticates.
    /// </summary>
    public sealed class NebulaHeaderCodec
    {
        /// <summary>Writes <paramref name="header"/> into <paramref name="destination"/> (length ≥ 16).</summary>
        public void Encode(NebulaHeader header, Span<byte> destination)
        {
            if (header is null) throw new ArgumentNullException(nameof(header));
            if (destination.Length < NebulaHeader.Size) throw new ArgumentException("destination must be >= 16 bytes", nameof(destination));

            destination[0] = (byte)((header.Version << 4) | ((int)header.Type & 0x0F));
            destination[1] = header.SubType;
            BinaryPrimitives.WriteUInt16BigEndian(destination.Slice(2, 2), header.Reserved);
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(4, 4), header.RemoteIndex);
            BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(8, 8), header.MessageCounter);
        }

        /// <summary>Allocates and returns the 16-byte encoding of <paramref name="header"/>.</summary>
        public byte[] Encode(NebulaHeader header)
        {
            byte[] buffer = new byte[NebulaHeader.Size];
            Encode(header, buffer);
            return buffer;
        }

        /// <summary>Builds a complete packet: the 16-byte header followed by <paramref name="payload"/>.</summary>
        public byte[] EncodePacket(NebulaHeader header, ReadOnlySpan<byte> payload)
        {
            byte[] packet = new byte[NebulaHeader.Size + payload.Length];
            Encode(header, packet);
            payload.CopyTo(packet.AsSpan(NebulaHeader.Size));
            return packet;
        }

        /// <summary>Parses the 16-byte header at the start of <paramref name="data"/>. Returns false if too short.</summary>
        public bool TryDecode(ReadOnlySpan<byte> data, out NebulaHeader header)
        {
            header = new NebulaHeader();
            if (data.Length < NebulaHeader.Size) return false;

            header.Version = (byte)((data[0] >> 4) & 0x0F);
            header.Type = (NebulaMessageType)(data[0] & 0x0F);
            header.SubType = data[1];
            header.Reserved = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(2, 2));
            header.RemoteIndex = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(4, 4));
            header.MessageCounter = BinaryPrimitives.ReadUInt64BigEndian(data.Slice(8, 8));
            return true;
        }
    }
}
