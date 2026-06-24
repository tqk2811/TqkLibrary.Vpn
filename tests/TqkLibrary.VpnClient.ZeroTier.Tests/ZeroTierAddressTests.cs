using TqkLibrary.VpnClient.ZeroTier.Identity.Models;
using Xunit;

namespace TqkLibrary.VpnClient.ZeroTier.Tests
{
    public class ZeroTierAddressTests
    {
        [Fact]
        public void Read_Write_RoundTrips_40Bits()
        {
            byte[] raw = { 0x80, 0x56, 0xC2, 0xE2, 0x1C };
            var addr = ZeroTierAddress.Read(raw);
            Assert.Equal("8056c2e21c", addr.ToString());

            byte[] outBytes = new byte[5];
            addr.Write(outBytes);
            Assert.Equal(raw, outBytes);
        }

        [Fact]
        public void Parse_ToString_RoundTrips()
        {
            var addr = ZeroTierAddress.Parse("deadbeef99");
            Assert.Equal("deadbeef99", addr.ToString());
            Assert.Equal(0xDEADBEEF99UL, addr.Value);
        }

        [Theory]
        [InlineData(0x0000000000UL, false)] // null
        [InlineData(0xFF00000001UL, false)] // 0xFF prefix reserved
        [InlineData(0x8056C2E21CUL, true)]
        public void IsValid_EnforcesReservedRules(ulong value, bool expected)
        {
            Assert.Equal(expected, new ZeroTierAddress(value).IsValid);
        }

        [Fact]
        public void Value_MasksAbove40Bits()
        {
            var addr = new ZeroTierAddress(0xAABB_CCDD_EEFF_1122UL);
            Assert.Equal(0xDDEEFF1122UL, addr.Value); // low 40 bits only
        }
    }
}
