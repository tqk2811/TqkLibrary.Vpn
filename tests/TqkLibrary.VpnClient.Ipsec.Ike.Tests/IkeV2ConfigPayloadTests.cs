using System.Net;
using TqkLibrary.VpnClient.Ipsec.Ike.V2;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Models;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Payloads;
using Xunit;

namespace TqkLibrary.VpnClient.Ipsec.Ike.Tests
{
    /// <summary>Wire-format round-trips for the IKEv2 Configuration Payload (RFC 7296 §3.15).</summary>
    public class IkeV2ConfigPayloadTests
    {
        [Fact]
        public void CfgRequest_RoundTrips_WithEmptyAttributes()
        {
            var cp = ConfigurationPayload.Request(); // default: IP4 address + netmask + DNS

            ConfigurationPayload decoded = RoundTrip(cp);

            Assert.Equal(IkeConfigType.Request, decoded.ConfigType);
            Assert.Equal(
                new[] { IkeConfigAttributeType.InternalIp4Address, IkeConfigAttributeType.InternalIp4Netmask, IkeConfigAttributeType.InternalIp4Dns },
                decoded.Attributes.Select(a => a.AttributeType));
            Assert.All(decoded.Attributes, a => Assert.Empty(a.Value)); // a request carries no values
        }

        [Fact]
        public void CfgReply_ExposesAssignedIpAndDnsServers()
        {
            var cp = new ConfigurationPayload { ConfigType = IkeConfigType.Reply };
            cp.Attributes.Add(new IkeConfigAttribute(IkeConfigAttributeType.InternalIp4Address, IPAddress.Parse("10.20.30.40").GetAddressBytes()));
            cp.Attributes.Add(new IkeConfigAttribute(IkeConfigAttributeType.InternalIp4Netmask, IPAddress.Parse("255.255.255.0").GetAddressBytes()));
            cp.Attributes.Add(new IkeConfigAttribute(IkeConfigAttributeType.InternalIp4Dns, IPAddress.Parse("8.8.8.8").GetAddressBytes()));
            cp.Attributes.Add(new IkeConfigAttribute(IkeConfigAttributeType.InternalIp4Dns, IPAddress.Parse("1.1.1.1").GetAddressBytes()));

            ConfigurationPayload decoded = RoundTrip(cp);

            Assert.Equal(IkeConfigType.Reply, decoded.ConfigType);
            Assert.Equal(IPAddress.Parse("10.20.30.40"), decoded.AssignedIp4Address);
            Assert.Equal(new[] { IPAddress.Parse("8.8.8.8"), IPAddress.Parse("1.1.1.1") }, decoded.DnsServers);
        }

        [Fact]
        public void CfgReply_ExposesAssignedIpv6Address_StrippingThePrefixLengthByte()
        {
            var cp = new ConfigurationPayload { ConfigType = IkeConfigType.Reply };
            byte[] addrPlusPrefix = IPAddress.Parse("2001:db8::1234").GetAddressBytes().Append((byte)64).ToArray(); // 16 + prefix len
            cp.Attributes.Add(new IkeConfigAttribute(IkeConfigAttributeType.InternalIp6Address, addrPlusPrefix));

            ConfigurationPayload decoded = RoundTrip(cp);

            Assert.Equal(IPAddress.Parse("2001:db8::1234"), decoded.AssignedIp6Address);
        }

        // Encode the CP inside a real IKE message body and parse it back through the payload chain.
        static ConfigurationPayload RoundTrip(ConfigurationPayload cp)
        {
            var message = new IkeMessage
            {
                InitiatorSpi = new byte[8],
                ResponderSpi = new byte[8],
                ExchangeType = IkeExchangeType.IkeAuth,
                Flags = IkeHeaderFlags.Initiator,
                MessageId = 1,
            };
            message.Payloads.Add(cp);
            IkeMessage decoded = IkeMessage.Decode(message.Encode());
            return decoded.Find<ConfigurationPayload>()!;
        }
    }
}
