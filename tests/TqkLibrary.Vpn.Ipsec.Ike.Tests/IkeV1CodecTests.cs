using TqkLibrary.Vpn.Ipsec.Ike.V1;
using TqkLibrary.Vpn.Ipsec.Ike.V1.Enums;
using TqkLibrary.Vpn.Ipsec.Ike.V1.Models;
using TqkLibrary.Vpn.Ipsec.Ike.V1.Payloads;
using Xunit;

namespace TqkLibrary.Vpn.Ipsec.Ike.Tests
{
    public class IkeV1CodecTests
    {
        [Fact]
        public void MainMode_Sa_RoundTrips_WithTransforms()
        {
            var message = new IsakmpMessage
            {
                InitiatorCookie = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 },
                ExchangeType = IsakmpExchangeType.MainMode,
                MessageId = 0,
            };
            message.Payloads.Add(IkeV1Proposals.Phase1());
            message.Payloads.Add(new IsakmpRawPayload(IsakmpPayloadType.VendorId, new byte[] { 0xAA, 0xBB }));

            IsakmpMessage decoded = IsakmpMessage.Decode(message.Encode());

            Assert.Equal(IsakmpExchangeType.MainMode, decoded.ExchangeType);
            Assert.Equal(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, decoded.InitiatorCookie);

            IsakmpSaPayload sa = decoded.Find<IsakmpSaPayload>()!;
            Assert.Equal(IkeV1Constants.IpsecDoi, sa.Doi);
            IsakmpProposal proposal = Assert.Single(sa.Proposals);
            Assert.Equal(IkeV1Constants.Protocol.Isakmp, proposal.ProtocolId);
            Assert.Equal(4, proposal.Transforms.Count);

            IsakmpTransform first = proposal.Transforms[0];
            Assert.Equal(IkeV1Constants.Phase1Encryption.AesCbc, AttrValue(first, IkeV1Constants.Phase1Attribute.Encryption));
            Assert.Equal(256u, AttrValue(first, IkeV1Constants.Phase1Attribute.KeyLength));
            Assert.Equal(IkeV1Constants.HashAlgorithm.Sha1, AttrValue(first, IkeV1Constants.Phase1Attribute.Hash));
            Assert.Equal(IkeV1Constants.AuthMethod.PreSharedKey, AttrValue(first, IkeV1Constants.Phase1Attribute.AuthMethod));
            Assert.Equal(28800u, AttrValue(first, IkeV1Constants.Phase1Attribute.LifeDuration));

            Assert.Equal(IsakmpPayloadType.VendorId, decoded.FindRaw(IsakmpPayloadType.VendorId)!.Type);
        }

        [Fact]
        public void QuickMode_Phase2Sa_WithSpi_RoundTrips()
        {
            byte[] spi = { 0x11, 0x22, 0x33, 0x44 };
            var message = new IsakmpMessage { ExchangeType = IsakmpExchangeType.QuickMode, MessageId = 0x12345678 };
            message.Payloads.Add(IkeV1Proposals.Phase2(spi));

            IsakmpMessage decoded = IsakmpMessage.Decode(message.Encode());
            Assert.Equal(0x12345678u, decoded.MessageId);

            IsakmpProposal proposal = decoded.Find<IsakmpSaPayload>()!.Proposals.Single();
            Assert.Equal(IkeV1Constants.Protocol.Esp, proposal.ProtocolId);
            Assert.Equal(spi, proposal.Spi);
            Assert.Equal(IkeV1Constants.EspTransform.Aes, proposal.Transforms[0].TransformId);
            Assert.Equal(IkeV1Constants.EncapsulationMode.UdpTransport,
                AttrValue(proposal.Transforms[0], IkeV1Constants.Phase2Attribute.EncapsulationMode));
        }

        [Fact]
        public void Attribute_LongForm_SurvivesRoundTrip()
        {
            // LifeDuration is encoded as a 4-byte TLV; KeyLength as a 2-byte TV. Both must survive a full round-trip.
            var message = new IsakmpMessage { ExchangeType = IsakmpExchangeType.MainMode };
            message.Payloads.Add(IkeV1Proposals.Phase1());

            IsakmpTransform transform = IsakmpMessage.Decode(message.Encode())
                .Find<IsakmpSaPayload>()!.Proposals.Single().Transforms[0];
            IsakmpAttribute lifeDuration = transform.Attributes.First(a => a.Type == IkeV1Constants.Phase1Attribute.LifeDuration);
            Assert.False(lifeDuration.IsShortForm);
            Assert.Equal(28800u, lifeDuration.NumericValue);
        }

        static uint AttrValue(IsakmpTransform transform, ushort type)
            => transform.Attributes.First(a => a.Type == type).NumericValue;
    }
}
