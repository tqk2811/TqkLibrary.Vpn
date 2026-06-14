using System.Net;
using TqkLibrary.VpnClient.Ethernet;
using Xunit;

namespace TqkLibrary.VpnClient.Ethernet.Tests
{
    public class ArpPacketTests
    {
        static readonly MacAddress MacA = MacAddress.Parse("02:00:00:00:00:0a");
        static readonly MacAddress MacB = MacAddress.Parse("02:00:00:00:00:0b");
        static readonly IPAddress IpA = IPAddress.Parse("10.0.0.1");
        static readonly IPAddress IpB = IPAddress.Parse("10.0.0.2");

        [Fact]
        public void BuildRequest_RoundTrips()
        {
            byte[] packet = ArpPacket.BuildRequest(MacA, IpA, IpB);

            Assert.Equal(ArpPacket.Length, packet.Length);
            Assert.True(ArpPacket.IsIpv4OverEthernet(packet));
            Assert.Equal(ArpPacket.OperationRequest, ArpPacket.Operation(packet));
            Assert.Equal(MacA, ArpPacket.SenderMac(packet));
            Assert.Equal(IpA, ArpPacket.SenderIp(packet));
            Assert.Equal(MacAddress.Zero, ArpPacket.TargetMac(packet));   // unknown target hardware in a request
            Assert.Equal(IpB, ArpPacket.TargetIp(packet));
        }

        [Fact]
        public void BuildReply_RoundTrips()
        {
            byte[] packet = ArpPacket.BuildReply(MacA, IpA, MacB, IpB);

            Assert.True(ArpPacket.IsIpv4OverEthernet(packet));
            Assert.Equal(ArpPacket.OperationReply, ArpPacket.Operation(packet));
            Assert.Equal(MacA, ArpPacket.SenderMac(packet));
            Assert.Equal(IpA, ArpPacket.SenderIp(packet));
            Assert.Equal(MacB, ArpPacket.TargetMac(packet));
            Assert.Equal(IpB, ArpPacket.TargetIp(packet));
        }

        [Fact]
        public void IsIpv4OverEthernet_RejectsTooShort()
        {
            Assert.False(ArpPacket.IsIpv4OverEthernet(new byte[ArpPacket.Length - 1]));
            Assert.False(ArpPacket.IsIpv4OverEthernet(new byte[ArpPacket.Length]));   // all-zero header (hw type 0)
        }

        [Fact]
        public void IsIpv4OverEthernet_RejectsWrongHardwareType()
        {
            byte[] packet = ArpPacket.BuildRequest(MacA, IpA, IpB);
            packet[1] = 6;   // hardware type 6, not Ethernet (1)
            Assert.False(ArpPacket.IsIpv4OverEthernet(packet));
        }

        [Fact]
        public void IsIpv4OverEthernet_RejectsWrongProtocolType()
        {
            byte[] packet = ArpPacket.BuildReply(MacA, IpA, MacB, IpB);
            packet[2] = 0x86;
            packet[3] = 0xDD;   // protocol type IPv6, not IPv4 (0x0800)
            Assert.False(ArpPacket.IsIpv4OverEthernet(packet));
        }
    }
}
