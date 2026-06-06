using TqkLibrary.Vpn.Ppp.Framing;
using Xunit;

namespace TqkLibrary.Vpn.Ppp.Tests
{
    public class HdlcFramingTests
    {
        static byte[] DecodeSingle(byte[] encoded)
        {
            var decoder = new HdlcDecoder();
            byte[]? captured = null;
            decoder.FrameReceived += f => captured = f.ToArray();
            decoder.Push(encoded);
            Assert.NotNull(captured);
            return captured!;
        }

        [Fact]
        public void Encode_Decode_Roundtrips()
        {
            // A typical LCP Configure-Request frame: Address FF, Control 03, Protocol C021, then LCP payload.
            byte[] frame = { 0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x08, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00 };
            byte[] encoded = HdlcFramer.Encode(frame);

            // Wrapped in flags.
            Assert.Equal(HdlcFramer.Flag, encoded[0]);
            Assert.Equal(HdlcFramer.Flag, encoded[^1]);

            Assert.Equal(frame, DecodeSingle(encoded));
        }

        [Fact]
        public void Encode_EscapesTransparencyBytes()
        {
            // Payload contains the flag (0x7E), escape (0x7D) and control bytes (< 0x20) that MUST be stuffed.
            byte[] frame = { 0xFF, 0x03, 0x00, 0x21, 0x7E, 0x7D, 0x00, 0x1F, 0x11, 0x13 };
            byte[] encoded = HdlcFramer.Encode(frame);

            // No raw 0x7E inside the frame body (only the two delimiters).
            for (int i = 1; i < encoded.Length - 1; i++)
                Assert.NotEqual(HdlcFramer.Flag, encoded[i]);

            Assert.Equal(frame, DecodeSingle(encoded));
        }

        [Fact]
        public void Decoder_DropsFrameWithBadFcs()
        {
            byte[] frame = { 0xFF, 0x03, 0xC0, 0x21, 0x09, 0x01, 0x00, 0x04 };
            byte[] encoded = HdlcFramer.Encode(frame);

            // Corrupt a content byte (between the flags).
            encoded[3] ^= 0xFF;

            var decoder = new HdlcDecoder();
            bool any = false;
            decoder.FrameReceived += _ => any = true;
            decoder.Push(encoded);
            Assert.False(any);
        }

        [Fact]
        public void Decoder_HandlesSplitChunks()
        {
            byte[] frame = { 0xFF, 0x03, 0x80, 0x21, 0x01, 0x01, 0x00, 0x0A, 0x03, 0x06, 0x0A, 0x00, 0x00, 0x01 };
            byte[] encoded = HdlcFramer.Encode(frame);

            var decoder = new HdlcDecoder();
            byte[]? captured = null;
            decoder.FrameReceived += f => captured = f.ToArray();
            // Feed one byte at a time.
            foreach (byte b in encoded) decoder.Push(new[] { b });

            Assert.Equal(frame, captured);
        }

        [Fact]
        public void Fcs16_GoodFcsProperty()
        {
            // RFC 1662 §C.2: running FCS over (content || transmitted-FCS) == 0xF0B8.
            byte[] content = { 0xFF, 0x03, 0xC0, 0x21, 0x01, 0x01, 0x00, 0x04 };
            ushort fcs = Fcs16.Compute(content);
            byte[] withFcs = new byte[content.Length + 2];
            content.CopyTo(withFcs, 0);
            withFcs[content.Length] = (byte)(fcs & 0xff);
            withFcs[content.Length + 1] = (byte)(fcs >> 8);

            ushort running = Fcs16.Update(Fcs16.InitFcs, withFcs);
            Assert.Equal(Fcs16.GoodFcs, running);
        }
    }
}
