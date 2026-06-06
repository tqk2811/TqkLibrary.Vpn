using System.Buffers;

namespace TqkLibrary.Vpn.Ppp.Framing
{
    /// <summary>
    /// HDLC-like async framing for PPP over a byte stream (RFC 1662): 0x7E flag delimiters, 0x7D escaping,
    /// and a trailing FCS-16. Used by SSTP (which carries HDLC-framed PPP). L2TP uses packet-mode instead.
    /// </summary>
    public static class HdlcFramer
    {
        /// <summary>Flag byte delimiting frames.</summary>
        public const byte Flag = 0x7E;

        /// <summary>Control-escape byte.</summary>
        public const byte ControlEscape = 0x7D;

        const byte TransparencyXor = 0x20;

        /// <summary>
        /// Frames <paramref name="frame"/> (Address+Control+Protocol+Information, without FCS) into a flagged,
        /// byte-stuffed HDLC frame with appended FCS-16.
        /// </summary>
        public static byte[] Encode(ReadOnlySpan<byte> frame)
        {
            ushort fcs = Fcs16.Compute(frame);
            var writer = new ArrayBufferWriter<byte>(frame.Length + 8);
            Append(writer, Flag);
            foreach (byte b in frame) EmitStuffed(writer, b);
            EmitStuffed(writer, (byte)(fcs & 0xff));
            EmitStuffed(writer, (byte)(fcs >> 8));
            Append(writer, Flag);
            return writer.WrittenSpan.ToArray();
        }

        static void EmitStuffed(IBufferWriter<byte> writer, byte b)
        {
            // Escape the two control bytes and all C0 control characters (default ACCM).
            if (b == Flag || b == ControlEscape || b < 0x20)
            {
                Append(writer, ControlEscape);
                Append(writer, (byte)(b ^ TransparencyXor));
            }
            else
            {
                Append(writer, b);
            }
        }

        static void Append(IBufferWriter<byte> writer, byte b)
        {
            Span<byte> span = writer.GetSpan(1);
            span[0] = b;
            writer.Advance(1);
        }
    }
}
