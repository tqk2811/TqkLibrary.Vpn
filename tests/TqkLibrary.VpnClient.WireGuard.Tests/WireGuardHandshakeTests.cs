using TqkLibrary.VpnClient.WireGuard;
using TqkLibrary.VpnClient.WireGuard.Handshake;
using TqkLibrary.VpnClient.WireGuard.Handshake.Models;
using Xunit;

namespace TqkLibrary.VpnClient.WireGuard.Tests
{
    /// <summary>
    /// Offline interop for the WireGuard Noise_IKpsk2 handshake (V3.b): an initiator and a responder run in the same
    /// process, exchange a type-1 initiation and a type-2 response through the byte codec, and must end up with the
    /// same crossed transport-key pair. No sockets, no timers — pure protocol logic.
    /// </summary>
    public class WireGuardHandshakeTests
    {
        static readonly WireGuardMessageCodec Codec = new();

        // A standalone X25519 group instance to mint static identities independent of any handshake.
        static WireGuardKeyPair NewStatic() => new WireGuardHandshake(
            new WireGuardKeyPair { PrivateKey = new byte[32], PublicKey = new byte[32] }).GenerateKeyPair();

        static (WireGuardHandshake initiator, WireGuardHandshake responder, WireGuardKeyPair iStatic, WireGuardKeyPair rStatic)
            BuildPair(byte[]? psk = null)
        {
            WireGuardKeyPair iStatic = NewStatic();
            WireGuardKeyPair rStatic = NewStatic();
            var initiator = new WireGuardHandshake(iStatic, remoteStaticPublic: rStatic.PublicKey, presharedKey: psk);
            var responder = new WireGuardHandshake(rStatic, remoteStaticPublic: null, presharedKey: psk);
            return (initiator, responder, iStatic, rStatic);
        }

        // ---- Full handshake interop ----

        [Fact]
        public void Handshake_Initiator_And_Responder_Agree_On_Crossed_Transport_Keys()
        {
            var (initiator, responder, iStatic, _) = BuildPair();

            // message1: initiator -> responder, through the wire codec.
            WireGuardInitiationMessage init = initiator.CreateInitiation(senderIndex: 0x11223344);
            byte[] wire1 = Codec.EncodeInitiation(init);
            Assert.Equal(WireGuardConstants.InitiationMessageLength, wire1.Length);
            Assert.True(Codec.TryDecodeInitiation(wire1, out WireGuardInitiationMessage init2));

            Assert.True(responder.ConsumeInitiation(init2, out byte[] recoveredStatic, out byte[] timestamp));
            Assert.Equal(iStatic.PublicKey, recoveredStatic);          // responder recovers the initiator's static key
            Assert.Equal(WireGuardTai64n.Length, timestamp.Length);

            // message2: responder -> initiator, through the wire codec.
            WireGuardResponseMessage resp = responder.CreateResponse(senderIndex: 0x55667788, receiverIndex: init.SenderIndex);
            byte[] wire2 = Codec.EncodeResponse(resp);
            Assert.Equal(WireGuardConstants.ResponseMessageLength, wire2.Length);
            Assert.True(Codec.TryDecodeResponse(wire2, out WireGuardResponseMessage resp2));
            Assert.Equal(init.SenderIndex, resp2.ReceiverIndex);       // initiator's index echoed back

            Assert.True(initiator.ConsumeResponse(resp2));

            // Split on both sides: this side's send key == peer's receive key (the pair is crossed).
            WireGuardTransportKeys iKeys = initiator.DeriveTransportKeys();
            WireGuardTransportKeys rKeys = responder.DeriveTransportKeys();

            Assert.Equal(32, iKeys.SendKey.Length);
            Assert.Equal(32, iKeys.ReceiveKey.Length);
            Assert.NotEqual(iKeys.SendKey, iKeys.ReceiveKey);

            Assert.Equal(iKeys.SendKey, rKeys.ReceiveKey);
            Assert.Equal(iKeys.ReceiveKey, rKeys.SendKey);
        }

        [Fact]
        public void Handshake_With_PresharedKey_Agrees()
        {
            byte[] psk = new byte[32];
            for (int i = 0; i < psk.Length; i++) psk[i] = (byte)(0xA0 + i);

            var (initiator, responder, _, _) = BuildPair(psk);

            WireGuardInitiationMessage init = initiator.CreateInitiation(1);
            Assert.True(responder.ConsumeInitiation(init, out _, out _));
            WireGuardResponseMessage resp = responder.CreateResponse(2, init.SenderIndex);
            Assert.True(initiator.ConsumeResponse(resp));

            WireGuardTransportKeys iKeys = initiator.DeriveTransportKeys();
            WireGuardTransportKeys rKeys = responder.DeriveTransportKeys();
            Assert.Equal(iKeys.SendKey, rKeys.ReceiveKey);
            Assert.Equal(iKeys.ReceiveKey, rKeys.SendKey);
        }

        [Fact]
        public void Handshake_PresharedKey_Mismatch_Fails_Response_Authentication()
        {
            byte[] pskA = new byte[32]; pskA[0] = 1;
            byte[] pskB = new byte[32]; pskB[0] = 2;

            WireGuardKeyPair iStatic = NewStatic();
            WireGuardKeyPair rStatic = NewStatic();
            var initiator = new WireGuardHandshake(iStatic, rStatic.PublicKey, presharedKey: pskA);
            var responder = new WireGuardHandshake(rStatic, presharedKey: pskB);

            WireGuardInitiationMessage init = initiator.CreateInitiation(1);
            Assert.True(responder.ConsumeInitiation(init, out _, out _)); // initiation has no PSK dependency
            WireGuardResponseMessage resp = responder.CreateResponse(2, init.SenderIndex);

            // The empty-payload tag binds the PSK, so a mismatched PSK breaks response authentication.
            Assert.False(initiator.ConsumeResponse(resp));
        }

        [Fact]
        public void ConsumeInitiation_Rejects_Tampered_EncryptedStatic()
        {
            var (initiator, responder, _, _) = BuildPair();
            WireGuardInitiationMessage init = initiator.CreateInitiation(1);

            byte[] badStatic = (byte[])init.EncryptedStatic.Clone();
            badStatic[^1] ^= 0xFF; // corrupt the tag
            var tampered = init with { EncryptedStatic = badStatic };

            Assert.False(responder.ConsumeInitiation(tampered, out _, out _));
        }

        [Fact]
        public void CreateInitiation_Without_RemoteStatic_Throws()
        {
            var initiator = new WireGuardHandshake(NewStatic()); // no remote static public
            Assert.Throws<InvalidOperationException>(() => initiator.CreateInitiation(1));
        }

        [Fact]
        public void CreateResponse_Before_ConsumeInitiation_Throws()
        {
            var responder = new WireGuardHandshake(NewStatic());
            Assert.Throws<InvalidOperationException>(() => responder.CreateResponse(1, 2));
        }

        // ---- Message codec ----

        [Fact]
        public void InitiationCodec_RoundTrips_Every_Field()
        {
            var msg = new WireGuardInitiationMessage
            {
                SenderIndex = 0xDEADBEEF,
                UnencryptedEphemeral = Fill(32, 0x10),
                EncryptedStatic = Fill(48, 0x20),
                EncryptedTimestamp = Fill(28, 0x30),
                Mac1 = Fill(16, 0x40),
                Mac2 = Fill(16, 0x50),
            };

            byte[] wire = Codec.EncodeInitiation(msg);
            Assert.Equal(WireGuardConstants.InitiationMessageLength, wire.Length);
            Assert.Equal(WireGuardConstants.MessageTypeInitiation, wire[0]);
            Assert.Equal(0, wire[1] | wire[2] | wire[3]); // reserved zero

            Assert.True(Codec.TryDecodeInitiation(wire, out WireGuardInitiationMessage back));
            Assert.Equal(msg.SenderIndex, back.SenderIndex);
            Assert.Equal(msg.UnencryptedEphemeral, back.UnencryptedEphemeral);
            Assert.Equal(msg.EncryptedStatic, back.EncryptedStatic);
            Assert.Equal(msg.EncryptedTimestamp, back.EncryptedTimestamp);
            Assert.Equal(msg.Mac1, back.Mac1);
            Assert.Equal(msg.Mac2, back.Mac2);
        }

        [Fact]
        public void ResponseCodec_RoundTrips_Every_Field()
        {
            var msg = new WireGuardResponseMessage
            {
                SenderIndex = 0x01020304,
                ReceiverIndex = 0x05060708,
                UnencryptedEphemeral = Fill(32, 0x60),
                EncryptedNothing = Fill(16, 0x70),
                Mac1 = Fill(16, 0x80),
                Mac2 = Fill(16, 0x90),
            };

            byte[] wire = Codec.EncodeResponse(msg);
            Assert.Equal(WireGuardConstants.ResponseMessageLength, wire.Length);
            Assert.Equal(WireGuardConstants.MessageTypeResponse, wire[0]);
            Assert.Equal(0, wire[1] | wire[2] | wire[3]);

            Assert.True(Codec.TryDecodeResponse(wire, out WireGuardResponseMessage back));
            Assert.Equal(msg.SenderIndex, back.SenderIndex);
            Assert.Equal(msg.ReceiverIndex, back.ReceiverIndex);
            Assert.Equal(msg.UnencryptedEphemeral, back.UnencryptedEphemeral);
            Assert.Equal(msg.EncryptedNothing, back.EncryptedNothing);
            Assert.Equal(msg.Mac1, back.Mac1);
            Assert.Equal(msg.Mac2, back.Mac2);
        }

        [Fact]
        public void Codec_Rejects_Wrong_Length_And_Type()
        {
            Assert.False(Codec.TryDecodeInitiation(new byte[WireGuardConstants.InitiationMessageLength - 1], out _));
            Assert.False(Codec.TryDecodeResponse(new byte[WireGuardConstants.ResponseMessageLength + 1], out _));

            byte[] wrongType = new byte[WireGuardConstants.InitiationMessageLength];
            wrongType[0] = WireGuardConstants.MessageTypeResponse; // type 2 in a type-1 slot
            Assert.False(Codec.TryDecodeInitiation(wrongType, out _));

            byte[] reservedSet = new byte[WireGuardConstants.InitiationMessageLength];
            reservedSet[0] = WireGuardConstants.MessageTypeInitiation;
            reservedSet[2] = 0x01; // a reserved byte must be zero
            Assert.False(Codec.TryDecodeInitiation(reservedSet, out _));
        }

        [Fact]
        public void EncodeInitiation_Rejects_Wrong_Sized_Field()
        {
            var bad = new WireGuardInitiationMessage
            {
                SenderIndex = 0,
                UnencryptedEphemeral = new byte[31], // wrong size
                EncryptedStatic = new byte[48],
                EncryptedTimestamp = new byte[28],
            };
            Assert.Throws<ArgumentException>(() => Codec.EncodeInitiation(bad));
        }

        // ---- TAI64N ----

        [Fact]
        public void Tai64n_Is_Monotonic_For_Increasing_Instants()
        {
            var tai = new WireGuardTai64n();
            var t0 = DateTimeOffset.FromUnixTimeMilliseconds(1_700_000_000_000);

            byte[] a = tai.Encode(t0);
            byte[] b = tai.Encode(t0.AddTicks(1));            // +100 ns
            byte[] c = tai.Encode(t0.AddSeconds(1));
            byte[] same = tai.Encode(t0);

            Assert.Equal(WireGuardTai64n.Length, a.Length);
            Assert.True(tai.Compare(a, b) < 0);
            Assert.True(tai.Compare(b, c) < 0);
            Assert.True(tai.Compare(a, c) < 0);
            Assert.Equal(0, tai.Compare(a, same));
            Assert.True(tai.Compare(c, a) > 0);
        }

        [Fact]
        public void Tai64n_Now_Advances_Or_Stays_Equal_Never_Goes_Back()
        {
            var tai = new WireGuardTai64n();
            byte[] first = tai.Now();
            byte[] second = tai.Now();
            Assert.True(tai.Compare(first, second) <= 0); // wall clock never moves backwards
        }

        [Fact]
        public void Tai64n_Seconds_Field_Uses_Tai_Base_BigEndian()
        {
            var tai = new WireGuardTai64n();
            // Unix second 0 → TAI seconds 0x400000000000000A, big-endian in the first 8 bytes.
            byte[] enc = tai.Encode(DateTimeOffset.FromUnixTimeSeconds(0));
            byte[] expectedSeconds = { 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A };
            Assert.Equal(expectedSeconds, enc[..8]);
            Assert.Equal(new byte[4], enc[8..]); // zero nanoseconds
        }

        static byte[] Fill(int length, byte value)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = value;
            return b;
        }
    }
}
