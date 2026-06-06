namespace TqkLibrary.Vpn.IpStack
{
    /// <summary>The one's-complement Internet checksum (RFC 1071) used by IPv4, TCP, UDP and ICMP.</summary>
    public static class InternetChecksum
    {
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
