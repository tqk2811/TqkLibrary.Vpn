using System.Globalization;

namespace TqkLibrary.Vpn.Ethernet
{
    /// <summary>
    /// A 48-bit IEEE 802 MAC address. Stored as a <see cref="ulong"/> (the six octets packed big-endian, octet 0 in
    /// the most-significant byte) so equality/hashing are cheap — it doubles as the key of the switch FDB (L2.1).
    /// </summary>
    public readonly struct MacAddress : IEquatable<MacAddress>
    {
        /// <summary>Number of octets in a MAC address.</summary>
        public const int Size = 6;

        readonly ulong _value;   // low 48 bits used; octet 0 = bits 40..47, octet 5 = bits 0..7

        MacAddress(ulong value) => _value = value & 0xFFFF_FFFF_FFFFUL;

        /// <summary>The broadcast address <c>ff:ff:ff:ff:ff:ff</c>.</summary>
        public static MacAddress Broadcast => new MacAddress(0xFFFF_FFFF_FFFFUL);

        /// <summary>The all-zero address <c>00:00:00:00:00:00</c>.</summary>
        public static MacAddress Zero => new MacAddress(0UL);

        /// <summary>The six octets packed into the low 48 bits of a <see cref="ulong"/> (octet 0 most significant).</summary>
        public ulong Value => _value;

        /// <summary>The first octet, whose low two bits carry the I/G (multicast) and U/L (local) flags.</summary>
        byte FirstOctet => (byte)(_value >> 40);

        /// <summary>True for the broadcast address <c>ff:ff:ff:ff:ff:ff</c>.</summary>
        public bool IsBroadcast => _value == 0xFFFF_FFFF_FFFFUL;

        /// <summary>True when the I/G bit (low bit of octet 0) is set — broadcast and all multicast groups.</summary>
        public bool IsMulticast => (FirstOctet & 0x01) != 0;

        /// <summary>True for an IPv6 multicast MAC (prefix <c>33:33</c>, RFC 2464 §7).</summary>
        public bool IsIpv6Multicast => FirstOctet == 0x33 && (byte)(_value >> 32) == 0x33;

        /// <summary>Builds a <see cref="MacAddress"/> from exactly six octets.</summary>
        public static MacAddress FromBytes(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length != Size)
                throw new ArgumentException($"A MAC address is {Size} bytes.", nameof(bytes));
            ulong value = 0;
            for (int i = 0; i < Size; i++)
                value = (value << 8) | bytes[i];
            return new MacAddress(value);
        }

        /// <summary>Writes the six octets (big-endian) into <paramref name="destination"/>.</summary>
        public void CopyTo(Span<byte> destination)
        {
            if (destination.Length < Size)
                throw new ArgumentException($"Need {Size} bytes.", nameof(destination));
            for (int i = 0; i < Size; i++)
                destination[i] = (byte)(_value >> (40 - i * 8));
        }

        /// <summary>Returns the six octets as a new array.</summary>
        public byte[] ToArray()
        {
            byte[] result = new byte[Size];
            CopyTo(result);
            return result;
        }

        /// <summary>Parses <c>aa:bb:cc:dd:ee:ff</c> (colon or dash separated). Throws on malformed input.</summary>
        public static MacAddress Parse(string text)
        {
            if (!TryParse(text, out MacAddress address))
                throw new FormatException($"'{text}' is not a valid MAC address.");
            return address;
        }

        /// <summary>Tries to parse <c>aa:bb:cc:dd:ee:ff</c> (colon or dash separated).</summary>
        public static bool TryParse(string? text, out MacAddress address)
        {
            address = default;
            if (text is null)
                return false;
            string[] parts = text.Split(':', '-');
            if (parts.Length != Size)
                return false;
            ulong value = 0;
            foreach (string part in parts)
            {
                if (part.Length != 2 || !byte.TryParse(part, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out byte octet))
                    return false;
                value = (value << 8) | octet;
            }
            address = new MacAddress(value);
            return true;
        }

        /// <summary>Formats as lower-case <c>aa:bb:cc:dd:ee:ff</c>.</summary>
        public override string ToString()
        {
            Span<byte> bytes = stackalloc byte[Size];
            CopyTo(bytes);
            return string.Join(":", bytes.ToArray().Select(b => b.ToString("x2", CultureInfo.InvariantCulture)));
        }

        public bool Equals(MacAddress other) => _value == other._value;
        public override bool Equals(object? obj) => obj is MacAddress other && Equals(other);
        public override int GetHashCode() => _value.GetHashCode();
        public static bool operator ==(MacAddress left, MacAddress right) => left._value == right._value;
        public static bool operator !=(MacAddress left, MacAddress right) => left._value != right._value;
    }
}
