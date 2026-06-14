using System.Buffers.Binary;
using System.Collections.Generic;

namespace TqkLibrary.VpnClient.OpenVpn.Transport
{
    /// <summary>
    /// OpenVPN's TCP packet framing (V2.g) — on a stream transport each OpenVPN packet is prefixed with a 16-bit
    /// big-endian length so the one-packet boundary <see cref="IOpenVpnTransport"/> assumes survives TCP's byte stream.
    /// This is the OpenVPN realisation of the F.2 <c>IPacketEncapsulator</c> seam (cf. SSTP's 4-byte framing).
    /// <see cref="Encode"/> prepends the length on egress; the instance decoder (<see cref="Append"/> +
    /// <see cref="TryReadPacket"/>) reassembles whole packets across arbitrary read boundaries — a packet split over
    /// several reads, or several packets coalesced into one read. The UDP transport needs none of this (one datagram
    /// already equals one packet).
    /// </summary>
    public sealed class OpenVpnTcpFraming
    {
        const int LengthPrefixSize = 2;

        /// <summary>The largest packet the 16-bit length prefix can carry.</summary>
        public const int MaxPacketLength = 0xFFFF;

        readonly List<byte> _buffer = new();

        /// <summary>Frames one outgoing packet as <c>length(2, big-endian) ‖ packet</c>.</summary>
        public static byte[] Encode(ReadOnlySpan<byte> packet)
        {
            if (packet.Length == 0) throw new ArgumentException("OpenVPN TCP frame cannot be empty.", nameof(packet));
            if (packet.Length > MaxPacketLength) throw new ArgumentOutOfRangeException(nameof(packet), "OpenVPN TCP frame exceeds 65535 bytes.");
            byte[] framed = new byte[LengthPrefixSize + packet.Length];
            BinaryPrimitives.WriteUInt16BigEndian(framed.AsSpan(0, LengthPrefixSize), (ushort)packet.Length);
            packet.CopyTo(framed.AsSpan(LengthPrefixSize));
            return framed;
        }

        /// <summary>Feeds a chunk of received stream bytes into the reassembly buffer.</summary>
        public void Append(ReadOnlySpan<byte> chunk)
        {
            // List<byte>.AddRange(ReadOnlySpan<byte>) isn't available on netstandard2.0; reads are MTU-sized so a
            // per-byte append is acceptable (zero-alloc reassembly is a Q.4 concern, not a correctness one).
            foreach (byte b in chunk) _buffer.Add(b);
        }

        /// <summary>
        /// Pulls the next fully-received packet if one is buffered; call in a loop after each <see cref="Append"/>.
        /// Returns false (leaving the partial bytes buffered) until a complete length-prefixed packet has arrived.
        /// </summary>
        public bool TryReadPacket(out byte[] packet)
        {
            packet = Array.Empty<byte>();
            if (_buffer.Count < LengthPrefixSize) return false;
            int length = (_buffer[0] << 8) | _buffer[1];
            if (_buffer.Count < LengthPrefixSize + length) return false;
            packet = new byte[length];
            for (int i = 0; i < length; i++) packet[i] = _buffer[LengthPrefixSize + i];
            _buffer.RemoveRange(0, LengthPrefixSize + length);
            return true;
        }
    }
}
