using TqkLibrary.Vpn.Ethernet;
using Xunit;

namespace TqkLibrary.Vpn.Ethernet.Tests
{
    public class EthernetFrameTests
    {
        [Theory]
        [InlineData(EthernetFrame.EtherTypeIpv4)]
        [InlineData(EthernetFrame.EtherTypeIpv6)]
        [InlineData(EthernetFrame.EtherTypeArp)]
        public void Build_And_Read_RoundTrip(ushort etherType)
        {
            MacAddress destination = MacAddress.Parse("ff:ff:ff:ff:ff:ff");
            MacAddress source = MacAddress.Parse("00:11:22:33:44:55");
            byte[] payload = { 0xDE, 0xAD, 0xBE, 0xEF };

            byte[] frame = EthernetFrame.Build(destination, source, etherType, payload);

            Assert.Equal(EthernetFrame.HeaderLength + payload.Length, frame.Length);
            Assert.Equal(destination, EthernetFrame.Destination(frame));
            Assert.Equal(source, EthernetFrame.Source(frame));
            Assert.Equal(etherType, EthernetFrame.EtherType(frame));
            Assert.Equal(payload, EthernetFrame.Payload(frame).ToArray());
        }

        [Fact]
        public void Header_Is_14_Bytes_With_BigEndian_EtherType()
        {
            byte[] frame = EthernetFrame.Build(
                MacAddress.Parse("01:02:03:04:05:06"),
                MacAddress.Parse("0a:0b:0c:0d:0e:0f"),
                EthernetFrame.EtherTypeIpv6,
                ReadOnlySpan<byte>.Empty);

            Assert.Equal(EthernetFrame.HeaderLength, frame.Length);
            // dst MAC | src MAC | EtherType (0x86DD big-endian)
            Assert.Equal(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }, frame[0..6]);
            Assert.Equal(new byte[] { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F }, frame[6..12]);
            Assert.Equal(0x86, frame[12]);
            Assert.Equal(0xDD, frame[13]);
            Assert.True(EthernetFrame.Payload(frame).IsEmpty);
        }

        [Fact]
        public void EtherType_Constants_HaveTheStandardValues()
        {
            Assert.Equal(0x0800, EthernetFrame.EtherTypeIpv4);
            Assert.Equal(0x86DD, EthernetFrame.EtherTypeIpv6);
            Assert.Equal(0x0806, EthernetFrame.EtherTypeArp);
        }
    }
}
