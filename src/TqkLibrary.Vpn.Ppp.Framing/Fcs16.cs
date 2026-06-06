namespace TqkLibrary.Vpn.Ppp.Framing
{
    /// <summary>PPP 16-bit Frame Check Sequence (RFC 1662, the reflected CRC-CCITT with polynomial 0x8408).</summary>
    public static class Fcs16
    {
        /// <summary>Good final FCS value after processing data + its transmitted FCS (RFC 1662 §C.2).</summary>
        public const ushort GoodFcs = 0xf0b8;

        /// <summary>Running-FCS initial value.</summary>
        public const ushort InitFcs = 0xffff;

        /// <summary>Updates a running FCS with more data (does NOT complement — for the good-FCS check).</summary>
        public static ushort Update(ushort fcs, ReadOnlySpan<byte> data)
        {
            foreach (byte b in data)
            {
                fcs ^= b;
                for (int i = 0; i < 8; i++)
                    fcs = (ushort)((fcs & 1) != 0 ? (fcs >> 1) ^ 0x8408 : fcs >> 1);
            }
            return fcs;
        }

        /// <summary>Computes the transmitted FCS (ones-complement of the running FCS) over <paramref name="data"/>.</summary>
        public static ushort Compute(ReadOnlySpan<byte> data) => (ushort)~Update(InitFcs, data);
    }
}
