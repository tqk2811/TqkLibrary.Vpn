namespace TqkLibrary.VpnClient.Ppp.Framing
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
            var output = new List<byte>(frame.Length + 8) { Flag };
            foreach (byte b in frame) EmitStuffed(output, b);
            EmitStuffed(output, (byte)(fcs & 0xff));
            EmitStuffed(output, (byte)(fcs >> 8));
            output.Add(Flag);
            return output.ToArray();
        }

        static void EmitStuffed(List<byte> output, byte b)
        {
            // Escape the two control bytes and all C0 control characters (default ACCM).
            if (b == Flag || b == ControlEscape || b < 0x20)
            {
                output.Add(ControlEscape);
                output.Add((byte)(b ^ TransparencyXor));
            }
            else
            {
                output.Add(b);
            }
        }
    }
}
