using System.Net;

namespace TqkLibrary.Vpn.IpStack
{
    /// <summary>The one's-complement Internet checksum (RFC 1071) used by IPv4, TCP, UDP and ICMP.</summary>
    public static class InternetChecksum
    {
        /// <summary>
        /// Accumulates the transport pseudo-header into a partial 32-bit sum, for both IPv4 (RFC 793/768: 4-byte
        /// addresses + 16-bit length) and IPv6 (RFC 8200 §8.1: 16-byte addresses + 32-bit Upper-Layer Packet Length).
        /// The address family is taken from the bytes of <paramref name="source"/>/<paramref name="destination"/>, so
        /// the same routine serves TCP, UDP and ICMPv6. Fold the result with <see cref="Finish"/> after adding the
        /// upper-layer bytes.
        /// </summary>
        public static uint PseudoHeaderSum(IPAddress source, IPAddress destination, byte protocol, int upperLayerLength)
        {
            uint sum = 0;
            byte[] s = source.GetAddressBytes();
            byte[] d = destination.GetAddressBytes();
            for (int i = 0; i + 1 < s.Length; i += 2) sum += (uint)((s[i] << 8) | s[i + 1]);
            for (int i = 0; i + 1 < d.Length; i += 2) sum += (uint)((d[i] << 8) | d[i + 1]);
            sum += (uint)((upperLayerLength >> 16) & 0xFFFF); // high word (zero for IPv4 lengths; the v6 length is 32-bit)
            sum += (uint)(upperLayerLength & 0xFFFF);
            sum += protocol;
            return sum;
        }

        /// <summary>Computes the 16-bit Internet checksum over <paramref name="data"/>.</summary>
        public static ushort Compute(ReadOnlySpan<byte> data)
        {
            uint sum = 0;
            int i = 0;
            for (; i + 1 < data.Length; i += 2)
                sum += (uint)((data[i] << 8) | data[i + 1]);
            if (i < data.Length)
                sum += (uint)(data[i] << 8);
            while ((sum >> 16) != 0)
                sum = (sum & 0xFFFF) + (sum >> 16);
            return (ushort)~sum;
        }

        /// <summary>Folds an already-accumulated 32-bit sum into the final 16-bit checksum.</summary>
        public static ushort Finish(uint sum)
        {
            while ((sum >> 16) != 0)
                sum = (sum & 0xFFFF) + (sum >> 16);
            return (ushort)~sum;
        }
    }
}
