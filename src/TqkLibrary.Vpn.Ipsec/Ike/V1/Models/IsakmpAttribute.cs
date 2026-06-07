namespace TqkLibrary.Vpn.Ipsec.Ike.V1.Models
{
    /// <summary>
    /// An ISAKMP SA attribute (RFC 2408 §3.3). The high bit of the type selects the form: set = Type/Value
    /// (a 2-byte value), clear = Type/Length/Value (a variable value such as a 4-byte life duration).
    /// </summary>
    public sealed class IsakmpAttribute
    {
        /// <summary>Attribute type (without the AF bit).</summary>
        public ushort Type { get; set; }

        /// <summary>True if encoded as Type/Value (2-byte value); false for Type/Length/Value.</summary>
        public bool IsShortForm { get; set; } = true;

        /// <summary>The 2-byte value for the short form.</summary>
        public ushort ShortValue { get; set; }

        /// <summary>The variable value for the long form.</summary>
        public byte[] LongValue { get; set; } = Array.Empty<byte>();

        /// <summary>Creates a Type/Value attribute.</summary>
        public static IsakmpAttribute Tv(ushort type, ushort value)
            => new() { Type = type, IsShortForm = true, ShortValue = value };

        /// <summary>Creates a Type/Length/Value attribute.</summary>
        public static IsakmpAttribute Tlv(ushort type, byte[] value)
            => new() { Type = type, IsShortForm = false, LongValue = value };

        /// <summary>Creates a Type/Length/Value attribute carrying a big-endian 32-bit value.</summary>
        public static IsakmpAttribute Tlv32(ushort type, uint value)
            => Tlv(type, new[] { (byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value });

        /// <summary>The value interpreted as an unsigned integer (works for both forms).</summary>
        public uint NumericValue
        {
            get
            {
                if (IsShortForm) return ShortValue;
                uint result = 0;
                foreach (byte b in LongValue) result = (result << 8) | b;
                return result;
            }
        }

        internal void Write(List<byte> output)
        {
            if (IsShortForm)
            {
                ushort typeWithAf = (ushort)(0x8000 | Type);
                output.Add((byte)(typeWithAf >> 8));
                output.Add((byte)typeWithAf);
                output.Add((byte)(ShortValue >> 8));
                output.Add((byte)ShortValue);
            }
            else
            {
                output.Add((byte)(Type >> 8));
                output.Add((byte)Type);
                output.Add((byte)(LongValue.Length >> 8));
                output.Add((byte)LongValue.Length);
                output.AddRange(LongValue);
            }
        }

        internal static IsakmpAttribute Parse(ReadOnlySpan<byte> data, out int consumed)
        {
            ushort rawType = (ushort)((data[0] << 8) | data[1]);
            bool shortForm = (rawType & 0x8000) != 0;
            ushort type = (ushort)(rawType & 0x7FFF);
            if (shortForm)
            {
                consumed = 4;
                return new IsakmpAttribute { Type = type, IsShortForm = true, ShortValue = (ushort)((data[2] << 8) | data[3]) };
            }

            int length = (data[2] << 8) | data[3];
            consumed = 4 + length;
            return new IsakmpAttribute { Type = type, IsShortForm = false, LongValue = data.Slice(4, length).ToArray() };
        }
    }
}
