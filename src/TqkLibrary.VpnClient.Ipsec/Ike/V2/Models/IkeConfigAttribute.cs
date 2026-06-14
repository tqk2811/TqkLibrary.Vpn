using System.Net;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V2.Models
{
    /// <summary>
    /// One Configuration Attribute (RFC 7296 §3.15.1): a 15-bit type, a 2-byte length, and an opaque value.
    /// In a CFG_REQUEST the value is empty (the client asks the responder to fill it in); in a CFG_REPLY it
    /// carries the assigned bytes (e.g. a 4-byte IPv4 address).
    /// </summary>
    public sealed class IkeConfigAttribute
    {
        /// <summary>The attribute type.</summary>
        public IkeConfigAttributeType AttributeType { get; }

        /// <summary>The attribute value (empty in a request).</summary>
        public byte[] Value { get; }

        /// <summary>Creates an attribute of the given type carrying <paramref name="value"/> (empty for a request).</summary>
        public IkeConfigAttribute(IkeConfigAttributeType type, byte[] value)
        {
            AttributeType = type;
            Value = value;
        }

        /// <summary>An empty (request) attribute of the given type.</summary>
        public static IkeConfigAttribute Request(IkeConfigAttributeType type) => new(type, Array.Empty<byte>());

        /// <summary>The value parsed as an <see cref="IPAddress"/> when it is a bare 4- or 16-byte address; otherwise null.</summary>
        public IPAddress? AsIpAddress => Value.Length is 4 or 16 ? new IPAddress(Value) : null;

        internal void Write(List<byte> output)
        {
            IkeBuffer.WriteUInt16(output, (ushort)((ushort)AttributeType & 0x7FFF)); // R bit (high) stays 0
            IkeBuffer.WriteUInt16(output, (ushort)Value.Length);
            output.AddRange(Value);
        }
    }
}
