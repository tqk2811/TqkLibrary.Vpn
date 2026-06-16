using TqkLibrary.VpnClient.Ipsec.Ike.V2;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Payloads;
using Xunit;

namespace TqkLibrary.VpnClient.Ipsec.Ike.Tests
{
    /// <summary>Wire-format round-trips for the IKEv2 Delete payload (RFC 7296 §3.11).</summary>
    public class IkeV2DeletePayloadTests
    {
        [Fact]
        public void EspDelete_CarriesProtocolAndSpis()
        {
            DeletePayload decoded = RoundTrip(DeletePayload.Esp(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }));

            Assert.Equal(IkeProtocolId.Esp, decoded.ProtocolId);
            Assert.Equal((byte)4, decoded.SpiSize);
            Assert.Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, Assert.Single(decoded.Spis));
        }

        [Fact]
        public void IkeDelete_HasNoSpis()
        {
            DeletePayload decoded = RoundTrip(DeletePayload.Ike());

            Assert.Equal(IkeProtocolId.Ike, decoded.ProtocolId);
            Assert.Equal((byte)0, decoded.SpiSize);
            Assert.Empty(decoded.Spis);
        }

        static DeletePayload RoundTrip(DeletePayload delete)
        {
            var message = new IkeMessage
            {
                InitiatorSpi = new byte[8],
                ResponderSpi = new byte[8],
                ExchangeType = IkeExchangeType.Informational,
                Flags = IkeHeaderFlags.Initiator,
                MessageId = 2,
            };
            message.Payloads.Add(delete);
            return IkeMessage.Decode(message.Encode()).Find<DeletePayload>()!;
        }
    }
}
