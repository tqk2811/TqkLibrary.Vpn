using TqkLibrary.VpnClient.Ipsec.Ike.V1;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Enums;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Payloads;
using Xunit;

namespace TqkLibrary.VpnClient.Ipsec.Ike.Tests
{
    /// <summary>
    /// Pins <see cref="IkeV1Client.TryReadRejectNotify"/> (P0.8a — forced-NAT-T diagnosis): the classifier that lets the
    /// L2TP/IPsec handshake fail fast with a clear reason when a gateway answers a Main/Quick Mode exchange with a
    /// clear-text error NOTIFY (e.g. it refuses forced NAT-T) instead of the expected reply — and that it never trips on
    /// a normal reply, a status notify (DPD/INITIAL-CONTACT), an Informational without a Notification, or junk. Also pins
    /// the generic notify-type reader it reuses (<see cref="IkeV1Dpd.TryReadNotifyType"/>).
    /// </summary>
    public class IkeV1RejectNotifyTests
    {
        static readonly byte[] CookieI = { 1, 2, 3, 4, 5, 6, 7, 8 };
        static readonly byte[] CookieR = { 9, 10, 11, 12, 13, 14, 15, 16 };

        // A cleartext ISAKMP Informational carrying the given payloads — the wire shape of an in-the-clear refusal.
        static byte[] Informational(params IsakmpPayload[] payloads)
        {
            var message = new IsakmpMessage
            {
                InitiatorCookie = CookieI,
                ResponderCookie = CookieR,
                ExchangeType = IsakmpExchangeType.Informational,
                MessageId = 0,
            };
            foreach (IsakmpPayload payload in payloads) message.Payloads.Add(payload);
            return message.Encode();
        }

        static IsakmpRawPayload Notify(ushort notifyType)
            => new(IsakmpPayloadType.Notification, IkeV1Dpd.BuildNotifyBody(CookieI, CookieR, notifyType, 0));

        [Theory]
        [InlineData((ushort)14)] // NO-PROPOSAL-CHOSEN
        [InlineData((ushort)18)] // INVALID-ID-INFORMATION
        [InlineData((ushort)24)] // AUTHENTICATION-FAILED
        [InlineData((ushort)1)]  // first error type
        [InlineData((ushort)16383)] // last error type
        public void ErrorNotify_IsClassifiedAsReject(ushort notifyType)
        {
            Assert.True(IkeV1Client.TryReadRejectNotify(Informational(Notify(notifyType)), out ushort got));
            Assert.Equal(notifyType, got);
        }

        [Theory]
        [InlineData(IkeV1Dpd.RUThere)]    // 36136 — DPD status notify
        [InlineData(IkeV1Dpd.RUThereAck)] // 36137
        [InlineData((ushort)16384)]       // first status type
        [InlineData((ushort)24578)]       // INITIAL-CONTACT (status)
        public void StatusNotify_IsNotReject(ushort notifyType)
            => Assert.False(IkeV1Client.TryReadRejectNotify(Informational(Notify(notifyType)), out _));

        [Fact]
        public void NormalMainModeReply_IsNotReject()
        {
            // A Main Mode reply (MM2/MM4 shape) is not an Informational → it must pass straight through, untouched.
            var message = new IsakmpMessage
            {
                InitiatorCookie = CookieI,
                ResponderCookie = CookieR,
                ExchangeType = IsakmpExchangeType.MainMode,
            };
            message.Payloads.Add(new IsakmpRawPayload(IsakmpPayloadType.Nonce, new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }));
            Assert.False(IkeV1Client.TryReadRejectNotify(message.Encode(), out _));
        }

        [Fact]
        public void InformationalWithoutNotification_IsNotReject()
        {
            // An Informational that carries no Notification (e.g. a Delete) is not a handshake-refusal signal.
            byte[] wire = Informational(new IsakmpRawPayload(IsakmpPayloadType.Delete, new byte[] { 0, 0, 0, 1, 1 }));
            Assert.False(IkeV1Client.TryReadRejectNotify(wire, out _));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(10)]
        [InlineData(27)] // one short of the 28-byte ISAKMP header
        public void TooShort_IsNotReject(int length)
            => Assert.False(IkeV1Client.TryReadRejectNotify(new byte[length], out _));

        [Fact]
        public void NullWire_IsNotReject() => Assert.False(IkeV1Client.TryReadRejectNotify(null!, out _));

        [Fact]
        public void TryReadNotifyType_ReadsTypeRegardlessOfValue()
        {
            byte[] body = IkeV1Dpd.BuildNotifyBody(CookieI, CookieR, 14, 0);
            Assert.True(IkeV1Dpd.TryReadNotifyType(body, out ushort type));
            Assert.Equal(14, type);

            Assert.False(IkeV1Dpd.TryReadNotifyType(new byte[7], out _)); // shorter than the 8-byte fixed prefix
            Assert.False(IkeV1Dpd.TryReadNotifyType(null!, out _));
        }
    }
}
