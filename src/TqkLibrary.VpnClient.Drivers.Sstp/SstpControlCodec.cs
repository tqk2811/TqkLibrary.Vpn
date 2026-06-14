using TqkLibrary.VpnClient.Drivers.Sstp.Enums;
using TqkLibrary.VpnClient.Drivers.Sstp.Models;

namespace TqkLibrary.VpnClient.Drivers.Sstp
{
    /// <summary>Builds/parses the body of an SSTP control packet: message type + attributes ([MS-SSTP] §2.2.2–2.2.3).</summary>
    public static class SstpControlCodec
    {
        /// <summary>Builds the control-message body (without the 4-byte SSTP packet header).</summary>
        public static byte[] BuildBody(SstpMessageType type, IReadOnlyList<SstpAttribute> attributes)
        {
            var output = new List<byte>(8)
            {
                (byte)((ushort)type >> 8), (byte)type,
                (byte)(attributes.Count >> 8), (byte)attributes.Count,
            };

            foreach (SstpAttribute attribute in attributes)
            {
                int length = 4 + attribute.Value.Length; // includes the 4-byte attribute header
                output.Add(0x00);                 // reserved
                output.Add(attribute.Id);         // attribute id
                output.Add((byte)(length >> 8));  // length (high)
                output.Add((byte)(length & 0xff)); // length (low)
                output.AddRange(attribute.Value);
            }

            return output.ToArray();
        }

        /// <summary>Parses a control-message body (the bytes after the 4-byte SSTP packet header).</summary>
        public static SstpControlMessage Parse(ReadOnlySpan<byte> body)
        {
            if (body.Length < 4) throw new ArgumentException("SSTP control body too short.", nameof(body));

            var type = (SstpMessageType)((body[0] << 8) | body[1]);
            int numAttributes = (body[2] << 8) | body[3];

            var attributes = new List<SstpAttribute>(numAttributes);
            int offset = 4;
            for (int i = 0; i < numAttributes && offset + 4 <= body.Length; i++)
            {
                byte id = body[offset + 1];
                int length = ((body[offset + 2] & 0x0F) << 8) | body[offset + 3]; // 12-bit length incl. header
                if (length < 4 || offset + length > body.Length) break;
                byte[] value = body.Slice(offset + 4, length - 4).ToArray();
                attributes.Add(new SstpAttribute(id, value));
                offset += length;
            }

            return new SstpControlMessage(type, attributes);
        }
    }
}
