using TqkLibrary.VpnClient.Ppp;
using TqkLibrary.VpnClient.Ppp.Enums;
using TqkLibrary.VpnClient.Ppp.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Ppp.Tests
{
    public class PppControlCodecTests
    {
        [Fact]
        public void BuildConfigure_Parse_Roundtrips()
        {
            var options = new[]
            {
                new PppOption((byte)LcpOptionType.Mru, new byte[] { 0x05, 0xDC }),          // MRU 1500
                new PppOption((byte)LcpOptionType.MagicNumber, new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }),
            };

            byte[] packet = PppControlCodec.BuildConfigure((byte)PppCode.ConfigureRequest, 0x42, options);

            PppControlPacket parsed = PppControlCodec.Parse(packet);
            Assert.Equal((byte)PppCode.ConfigureRequest, parsed.Code);
            Assert.Equal(0x42, parsed.Identifier);

            List<PppOption> parsedOptions = PppControlCodec.ParseOptions(parsed.Data);
            Assert.Equal(2, parsedOptions.Count);
            Assert.Equal((byte)LcpOptionType.Mru, parsedOptions[0].Type);
            Assert.Equal(new byte[] { 0x05, 0xDC }, parsedOptions[0].Data);
            Assert.Equal((byte)LcpOptionType.MagicNumber, parsedOptions[1].Type);
            Assert.Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, parsedOptions[1].Data);
        }

        [Fact]
        public void Parse_KnownLcpConfigureRequest()
        {
            // Code=01 (Configure-Request) Id=01 Length=000A ; option: MagicNumber(05) len 06 = 00000000
            byte[] bytes = { 0x01, 0x01, 0x00, 0x0A, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00 };

            PppControlPacket parsed = PppControlCodec.Parse(bytes);
            Assert.Equal((byte)PppCode.ConfigureRequest, parsed.Code);
            Assert.Equal(0x01, parsed.Identifier);

            List<PppOption> options = PppControlCodec.ParseOptions(parsed.Data);
            PppOption magic = Assert.Single(options);
            Assert.Equal((byte)LcpOptionType.MagicNumber, magic.Type);
            Assert.Equal(new byte[] { 0x00, 0x00, 0x00, 0x00 }, magic.Data);
        }

        [Fact]
        public void Build_EncodesLengthBigEndian()
        {
            byte[] packet = PppControlCodec.Build((byte)PppCode.EchoRequest, 0x07, new byte[] { 0x01, 0x02, 0x03 });
            Assert.Equal((byte)PppCode.EchoRequest, packet[0]);
            Assert.Equal(0x07, packet[1]);
            Assert.Equal(0x00, packet[2]);
            Assert.Equal(0x07, packet[3]); // 4 header + 3 data
            Assert.Equal(7, packet.Length);
        }

        [Fact]
        public void ParseOptions_StopsOnMalformedTail()
        {
            // Valid MRU option (type 1, len 4) followed by a truncated option (len says 6 but only 1 byte left).
            byte[] data = { 0x01, 0x04, 0x05, 0xDC, 0x05, 0x06, 0x00 };
            List<PppOption> options = PppControlCodec.ParseOptions(data);
            Assert.Single(options);
            Assert.Equal(0x01, options[0].Type);
        }
    }
}
