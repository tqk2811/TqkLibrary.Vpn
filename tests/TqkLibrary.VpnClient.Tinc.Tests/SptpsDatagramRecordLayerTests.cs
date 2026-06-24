using TqkLibrary.VpnClient.Tinc.Sptps;
using TqkLibrary.VpnClient.Tinc.Sptps.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Tinc.Tests
{
    /// <summary>UDP datagram (data plane) record codec: round-trip, replay-window, tamper and reorder behaviour.</summary>
    public class SptpsDatagramRecordLayerTests
    {
        static byte[] Key(byte seed)
        {
            byte[] k = new byte[TincChaChaPoly1305.KeyLength];
            for (int i = 0; i < k.Length; i++) k[i] = (byte)(seed + i);
            return k;
        }

        static (SptpsDatagramRecordLayer a, SptpsDatagramRecordLayer b) Pair()
        {
            byte[] aToB = Key(1), bToA = Key(100);
            return (new SptpsDatagramRecordLayer(aToB, bToA), new SptpsDatagramRecordLayer(bToA, aToB));
        }

        [Fact]
        public void Datagram_RoundTrips_WithSeqnoPrefix()
        {
            var (a, b) = Pair();
            byte[] payload = { 0x45, 0x00, 0x00, 0x1c }; // looks like an IPv4 header start
            byte[] frame = a.Encode(0, payload);
            Assert.Equal(4 + 1 + payload.Length + TincChaChaPoly1305.TagLength, frame.Length);
            Assert.Equal(0u, (uint)((frame[0] << 24) | (frame[1] << 16) | (frame[2] << 8) | frame[3])); // first seqno = 0

            Assert.Equal(SptpsDecodeResult.Ok, b.Decode(frame, out byte type, out byte[] data));
            Assert.Equal(0, type);
            Assert.Equal(payload, data);
        }

        [Fact]
        public void Datagram_Replay_Rejected()
        {
            var (a, b) = Pair();
            byte[] frame = a.Encode(0, new byte[] { 1, 2, 3 });
            Assert.Equal(SptpsDecodeResult.Ok, b.Decode(frame, out _, out _));
            // Replaying the same datagram is rejected by the window.
            Assert.Equal(SptpsDecodeResult.AuthFailed, b.Decode(frame, out _, out _));
        }

        [Fact]
        public void Datagram_OutOfOrderWithinWindow_Accepted()
        {
            var (a, b) = Pair();
            byte[] f0 = a.Encode(0, new byte[] { 0 });
            byte[] f1 = a.Encode(0, new byte[] { 1 });
            byte[] f2 = a.Encode(0, new byte[] { 2 });

            // Deliver 2, then 0, then 1 — all distinct seqnos within the window → all accepted once.
            Assert.Equal(SptpsDecodeResult.Ok, b.Decode(f2, out _, out _));
            Assert.Equal(SptpsDecodeResult.Ok, b.Decode(f0, out _, out _));
            Assert.Equal(SptpsDecodeResult.Ok, b.Decode(f1, out _, out _));
            // Re-deliver 0 → replay.
            Assert.Equal(SptpsDecodeResult.AuthFailed, b.Decode(f0, out _, out _));
        }

        [Fact]
        public void Datagram_Tampered_Rejected()
        {
            var (a, b) = Pair();
            byte[] frame = a.Encode(0, new byte[] { 9, 9, 9 });
            frame[6] ^= 0x40; // flip a ciphertext byte
            Assert.Equal(SptpsDecodeResult.AuthFailed, b.Decode(frame, out _, out _));
        }
    }
}
