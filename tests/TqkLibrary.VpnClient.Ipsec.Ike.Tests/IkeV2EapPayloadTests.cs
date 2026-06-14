using TqkLibrary.VpnClient.Ipsec.Ike.V2;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Eap;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V2.Payloads;
using Xunit;

namespace TqkLibrary.VpnClient.Ipsec.Ike.Tests
{
    /// <summary>Wire-format round-trips for the IKEv2 EAP payload (RFC 7296 §3.16, EAP packet RFC 3748 §4).</summary>
    public class IkeV2EapPayloadTests
    {
        [Fact]
        public void EapRequest_RoundTripsThroughTheParseDispatch()
        {
            // EAP-Request/MSCHAPv2 Challenge-ish packet: Code=1, Id=0x42, Length, Type=26, opaque type-data.
            byte[] eap = { 0x01, 0x42, 0x00, 0x09, 26, 0x01, 0x00, 0x05, 0x10 };
            EapPayload decoded = RoundTrip(new EapPayload { Message = eap });

            Assert.Equal(eap, decoded.Message);
            Assert.Equal(EapCode.Request, decoded.Code);
            Assert.Equal((byte)0x42, decoded.Identifier);
        }

        [Fact]
        public void EapSuccess_RoundTrips()
        {
            // EAP-Success has no Type/Type-Data: Code=3, Id, Length=4.
            byte[] eap = { 0x03, 0x07, 0x00, 0x04 };
            EapPayload decoded = RoundTrip(new EapPayload { Message = eap });

            Assert.Equal(eap, decoded.Message);
            Assert.Equal(EapCode.Success, decoded.Code);
            Assert.Equal((byte)0x07, decoded.Identifier);
        }

        static EapPayload RoundTrip(EapPayload eap)
        {
            var message = new IkeMessage
            {
                InitiatorSpi = new byte[8],
                ResponderSpi = new byte[8],
                ExchangeType = IkeExchangeType.IkeAuth,
                Flags = IkeHeaderFlags.Initiator,
                MessageId = 2,
            };
            message.Payloads.Add(eap);
            return IkeMessage.Decode(message.Encode()).Find<EapPayload>()!;
        }
    }
}
