namespace TqkLibrary.Vpn.Drivers.Sstp.Models
{
    /// <summary>One SSTP control-message attribute (Reserved + Id + Length + Value).</summary>
    public sealed class SstpAttribute
    {
        /// <summary>Creates an attribute.</summary>
        public SstpAttribute(byte id, byte[] value)
        {
            Id = id;
            Value = value ?? Array.Empty<byte>();
        }

        /// <summary>Attribute ID (see <see cref="Enums.SstpAttributeId"/>).</summary>
        public byte Id { get; }

        /// <summary>Attribute value (the bytes after the 4-byte attribute header).</summary>
        public byte[] Value { get; }
    }
}
