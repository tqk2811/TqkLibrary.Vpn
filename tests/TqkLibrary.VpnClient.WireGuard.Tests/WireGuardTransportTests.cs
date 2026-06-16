using System.Buffers.Binary;
using TqkLibrary.VpnClient.WireGuard;
using TqkLibrary.VpnClient.WireGuard.DataChannel;
using TqkLibrary.VpnClient.WireGuard.Handshake;
using TqkLibrary.VpnClient.WireGuard.Handshake.Models;
using Xunit;

namespace TqkLibrary.VpnClient.WireGuard.Tests
{
    /// <summary>
    /// Offline tests for the WireGuard transport (data) channel (V3.d): seal→open round-trips both ways between two
    /// transports built from the crossed handshake keys, the counter advances, replays / out-of-window counters / bad
    /// tags are dropped, keepalives carry an empty payload, and the type-4 wire layout matches the whitepaper. Pure
    /// crypto/codec logic — no sockets, no timers.
    /// </summary>
    public class WireGuardTransportTests
    {
        // ---- helpers ----

        static WireGuardKeyPair NewStatic() => new WireGuardHandshake(
            new WireGuardKeyPair { PrivateKey = new byte[32], PublicKey = new byte[32] }).GenerateKeyPair();

        /// <summary>Runs a full handshake and returns the two transports + the indices each side chose.</summary>
        static (WireGuardTransport initiator, WireGuardTransport responder) BuildTransports(
            uint initiatorIndex = 0x11111111, uint responderIndex = 0x22222222)
        {
            WireGuardKeyPair iStatic = NewStatic();
            WireGuardKeyPair rStatic = NewStatic();
            var initiatorHs = new WireGuardHandshake(iStatic, remoteStaticPublic: rStatic.PublicKey);
            var responderHs = new WireGuardHandshake(rStatic);

            WireGuardInitiationMessage init = initiatorHs.CreateInitiation(initiatorIndex);
            Assert.True(responderHs.ConsumeInitiation(init, out _, out _));
            WireGuardResponseMessage resp = responderHs.CreateResponse(responderIndex, init.SenderIndex);
            Assert.True(initiatorHs.ConsumeResponse(resp));

            WireGuardTransportKeys iKeys = initiatorHs.DeriveTransportKeys();
            WireGuardTransportKeys rKeys = responderHs.DeriveTransportKeys();

            // The initiator seals toward the responder's index and accepts datagrams addressed to its own, and vice versa.
            var initiator = new WireGuardTransport(iKeys, sendReceiverIndex: responderIndex, localReceiverIndex: initiatorIndex);
            var responder = new WireGuardTransport(rKeys, sendReceiverIndex: initiatorIndex, localReceiverIndex: responderIndex);
            return (initiator, responder);
        }

        static byte[] Payload(int length, byte seed)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = (byte)(seed + i);
            return b;
        }

        // ---- round-trip both ways ----

        [Fact]
        public void Seal_Open_RoundTrips_Both_Directions()
        {
            var (initiator, responder) = BuildTransports();

            byte[] toResponder = Payload(100, 0x10);
            byte[] wireA = initiator.Seal(toResponder);
            Assert.True(responder.TryOpen(wireA, out byte[] gotA));
            Assert.Equal(toResponder, gotA);

            byte[] toInitiator = Payload(60, 0x80);
            byte[] wireB = responder.Seal(toInitiator);
            Assert.True(initiator.TryOpen(wireB, out byte[] gotB));
            Assert.Equal(toInitiator, gotB);
        }

        [Fact]
        public void Seal_Open_Many_Packets_In_Order()
        {
            var (initiator, responder) = BuildTransports();
            for (int i = 0; i < 300; i++)
            {
                byte[] msg = Payload(40, (byte)i);
                byte[] wire = initiator.Seal(msg);
                Assert.True(responder.TryOpen(wire, out byte[] got));
                Assert.Equal(msg, got);
            }
            Assert.Equal(300UL, initiator.SentPacketCount);
            Assert.Equal(299UL, responder.HighestReceivedCounter); // counters 0..299, highest is 299
        }

        // ---- counter advances, first counter is 0, encoded little-endian ----

        [Fact]
        public void Counter_Starts_At_Zero_And_Advances()
        {
            var (initiator, _) = BuildTransports();
            Assert.Equal(0UL, initiator.SentPacketCount);

            byte[] w0 = initiator.Seal(Payload(8, 1));
            Assert.Equal(1UL, initiator.SentPacketCount);
            byte[] w1 = initiator.Seal(Payload(8, 2));
            Assert.Equal(2UL, initiator.SentPacketCount);

            // counter field sits at offset 8, little-endian, 8 bytes.
            Assert.Equal(0UL, BinaryPrimitives.ReadUInt64LittleEndian(w0.AsSpan(8, 8)));
            Assert.Equal(1UL, BinaryPrimitives.ReadUInt64LittleEndian(w1.AsSpan(8, 8)));
        }

        // ---- replay / out-of-window rejection ----

        [Fact]
        public void Replay_Of_Same_Datagram_Is_Rejected()
        {
            var (initiator, responder) = BuildTransports();
            byte[] wire = initiator.Seal(Payload(20, 5));

            Assert.True(responder.TryOpen(wire, out _));   // first delivery accepted
            Assert.False(responder.TryOpen(wire, out _));  // exact replay dropped
        }

        [Fact]
        public void OutOfOrder_Within_Window_Accepted_Once_Then_Replay_Dropped()
        {
            var (initiator, responder) = BuildTransports();

            // Seal a burst, then deliver out of order: 5, then 2, then 2 again.
            byte[][] wires = new byte[10][];
            for (int i = 0; i < wires.Length; i++) wires[i] = initiator.Seal(Payload(16, (byte)i));

            Assert.True(responder.TryOpen(wires[5], out _));   // highest = counter 5
            Assert.True(responder.TryOpen(wires[2], out _));   // 3 behind, within window, unseen → accepted
            Assert.False(responder.TryOpen(wires[2], out _));  // now seen → replay
            Assert.True(responder.TryOpen(wires[0], out _));   // 5 behind, still in window, unseen → accepted
        }

        [Fact]
        public void Counter_Older_Than_Window_Is_Rejected()
        {
            var (initiator, responder) = BuildTransports();

            // Build counter 0 first, then advance the receiver far past the window with counter 100.
            byte[] old = initiator.Seal(Payload(16, 0xAA));     // counter 0
            for (int i = 1; i < 100; i++) initiator.Seal(Payload(16, (byte)i)); // discard counters 1..99
            byte[] far = initiator.Seal(Payload(16, 0xBB));     // counter 100

            Assert.True(responder.TryOpen(far, out _));         // highest = 100
            Assert.False(responder.TryOpen(old, out _));        // counter 0 is 100 behind → outside the 64 window
        }

        // ---- bad tag / tampering ----

        [Fact]
        public void Tampered_Tag_Is_Rejected()
        {
            var (initiator, responder) = BuildTransports();
            byte[] wire = initiator.Seal(Payload(32, 0x33));
            wire[^1] ^= 0xFF; // corrupt the last tag byte
            Assert.False(responder.TryOpen(wire, out _));
        }

        [Fact]
        public void Tampered_Ciphertext_Is_Rejected()
        {
            var (initiator, responder) = BuildTransports();
            byte[] wire = initiator.Seal(Payload(32, 0x44));
            wire[WireGuardDataCodec.HeaderLength] ^= 0x01; // flip a ciphertext bit
            Assert.False(responder.TryOpen(wire, out _));
        }

        [Fact]
        public void Wrong_Key_Cannot_Open()
        {
            var (initiator, _) = BuildTransports(0xAAAA0001, 0xAAAA0002);
            var (_, otherResponder) = BuildTransports(0xAAAA0001, 0xAAAA0002); // different session, same indices
            byte[] wire = initiator.Seal(Payload(24, 0x55));
            Assert.False(otherResponder.TryOpen(wire, out _)); // tag fails under unrelated keys
        }

        // ---- receiver-index addressing ----

        [Fact]
        public void Datagram_For_Different_Receiver_Index_Is_Dropped()
        {
            var (initiator, responder) = BuildTransports(0x01010101, 0x02020202);
            byte[] wire = initiator.Seal(Payload(16, 0x66));
            // Rewrite the receiver index to a value the responder does not own.
            BinaryPrimitives.WriteUInt32LittleEndian(wire.AsSpan(4, 4), 0xDEADBEEF);
            Assert.False(responder.TryOpen(wire, out _)); // dropped before the AEAD
        }

        // ---- keepalive ----

        [Fact]
        public void Keepalive_Has_Empty_Payload_And_Opens_To_Zero_Length()
        {
            var (initiator, responder) = BuildTransports();
            byte[] ka = initiator.Keepalive();

            Assert.Equal(WireGuardDataCodec.MinimumLength, ka.Length); // header + tag only, no ciphertext
            Assert.Equal(WireGuardConstants.MessageTypeTransportData, ka[0]);

            Assert.True(responder.TryOpen(ka, out byte[] payload));
            Assert.Empty(payload); // an authenticated empty packet — callers do not forward it
        }

        // ---- codec layout + malformed rejection ----

        [Fact]
        public void Codec_Header_RoundTrips_Type_Receiver_Counter()
        {
            var codec = new WireGuardDataCodec();
            byte[] buf = new byte[WireGuardDataCodec.MinimumLength];
            codec.WriteHeader(buf, receiverIndex: 0xA1B2C3D4, counter: 0x0102030405060708UL);

            Assert.Equal(WireGuardConstants.MessageTypeTransportData, buf[0]);
            Assert.Equal(0, buf[1] | buf[2] | buf[3]); // reserved zero
            Assert.Equal(0xA1B2C3D4u, BinaryPrimitives.ReadUInt32LittleEndian(buf.AsSpan(4, 4)));
            Assert.Equal(0x0102030405060708UL, BinaryPrimitives.ReadUInt64LittleEndian(buf.AsSpan(8, 8)));

            Assert.True(codec.TryReadHeader(buf, out uint rx, out ulong ctr));
            Assert.Equal(0xA1B2C3D4u, rx);
            Assert.Equal(0x0102030405060708UL, ctr);
        }

        [Fact]
        public void Codec_Nonce_Is_Four_Zeroes_Then_LittleEndian_Counter()
        {
            var codec = new WireGuardDataCodec();
            byte[] nonce = new byte[WireGuardDataCodec.NonceLength];
            codec.WriteNonce(nonce, 0x1122334455667788UL);

            Assert.Equal(new byte[] { 0, 0, 0, 0 }, nonce[..4]);
            Assert.Equal(0x1122334455667788UL, BinaryPrimitives.ReadUInt64LittleEndian(nonce.AsSpan(4, 8)));
        }

        [Fact]
        public void Codec_Rejects_Malformed_Header()
        {
            var codec = new WireGuardDataCodec();

            Assert.False(codec.TryReadHeader(new byte[WireGuardDataCodec.MinimumLength - 1], out _, out _)); // too short

            byte[] wrongType = new byte[WireGuardDataCodec.MinimumLength];
            wrongType[0] = WireGuardConstants.MessageTypeInitiation; // not type 4
            Assert.False(codec.TryReadHeader(wrongType, out _, out _));

            byte[] reservedSet = new byte[WireGuardDataCodec.MinimumLength];
            reservedSet[0] = WireGuardConstants.MessageTypeTransportData;
            reservedSet[2] = 0x01; // reserved byte must be zero
            Assert.False(codec.TryReadHeader(reservedSet, out _, out _));
        }

        // ---- 64-bit replay protector unit behaviour (full u64 counter, 0-based) ----

        [Fact]
        public void Replay_Protector_Accepts_Counter_Zero_First()
        {
            var rp = new WireGuardReplayProtector();
            Assert.True(rp.Check(0));   // WireGuard's first counter is 0, unlike ESP/OpenVPN's 1
            rp.Commit(0);
            Assert.False(rp.Check(0));  // now seen
            Assert.Equal(0UL, rp.Highest);
        }

        [Fact]
        public void Replay_Protector_Sliding_Window_Over_u64()
        {
            var rp = new WireGuardReplayProtector();
            // Commit only the even counters 0,2,4,…,198 so odd ones stay unseen within the window.
            for (ulong c = 0; c <= 198; c += 2) { Assert.True(rp.Check(c)); rp.Commit(c); }
            Assert.Equal(198UL, rp.Highest);

            Assert.False(rp.Check(198 - 64)); // exactly at the edge → too old
            Assert.False(rp.Check(0));        // far behind → too old
            Assert.False(rp.Check(198));      // committed (even) → replay
            Assert.True(rp.Check(197));       // odd, within window, never committed → accepted
            rp.Commit(197);
            Assert.False(rp.Check(197));       // now seen → replay
        }

        [Fact]
        public void Replay_Protector_Handles_High_32_Bit_Epoch_Advance()
        {
            var rp = new WireGuardReplayProtector();
            // A counter just below 2^32 and one just above — the low 32 bits wrap, exercising the high-half tracking.
            ulong belowBoundary = (1UL << 32) - 1; // 0x00000000_FFFFFFFF
            ulong aboveBoundary = (1UL << 32) + 5;  // 0x00000001_00000005

            Assert.True(rp.Check(belowBoundary)); rp.Commit(belowBoundary);
            Assert.Equal(belowBoundary, rp.Highest);

            Assert.True(rp.Check(aboveBoundary));  // higher epoch → ahead of the window
            rp.Commit(aboveBoundary);
            Assert.Equal(aboveBoundary, rp.Highest);

            Assert.False(rp.Check(belowBoundary)); // older epoch → replay
            Assert.True(rp.Check(aboveBoundary - 1)); // same epoch, 1 behind, unseen → accepted
        }

        [Fact]
        public void Seal_Overflow_Would_Require_Rekey()
        {
            // The send counter is u64 and only ever increments; reaching 2^64 in a test is infeasible, so this just
            // documents that SentPacketCount tracks the next counter and overflow is guarded in Seal.
            var (initiator, _) = BuildTransports();
            initiator.Seal(Payload(4, 1));
            Assert.Equal(1UL, initiator.SentPacketCount);
        }
    }
}
