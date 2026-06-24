using TqkLibrary.VpnClient.Tinc.Sptps;
using TqkLibrary.VpnClient.Tinc.Sptps.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Tinc.Tests
{
    /// <summary>Stream record framing in both the plaintext (handshake) and encrypted (post-handshake) phases.</summary>
    public class SptpsRecordLayerTests
    {
        static byte[] Key(byte seed)
        {
            byte[] k = new byte[TincChaChaPoly1305.KeyLength];
            for (int i = 0; i < k.Length; i++) k[i] = (byte)(seed + i);
            return k;
        }

        [Fact]
        public void Plaintext_HandshakeRecord_RoundTrips()
        {
            var send = new SptpsRecordLayer();
            var recv = new SptpsRecordLayer();
            byte[] payload = { 10, 20, 30, 40 };

            byte[] frame = send.EncodeHandshake(payload);
            var result = recv.TryDecodeRecord(frame, out byte type, out byte[] data, out int consumed);

            Assert.Equal(SptpsDecodeResult.Ok, result);
            Assert.Equal((byte)SptpsRecordType.Handshake, type);
            Assert.Equal(payload, data);
            Assert.Equal(frame.Length, consumed);
        }

        [Fact]
        public void Encrypted_AppRecord_RoundTrips_AcrossDirections()
        {
            byte[] aToB = Key(1);
            byte[] bToA = Key(100);

            var a = new SptpsRecordLayer();
            var b = new SptpsRecordLayer();
            a.EnableEncryption(aToB, bToA);
            b.EnableEncryption(bToA, aToB);

            byte[] msg = System.Text.Encoding.ASCII.GetBytes("12 server node2 1.2.3.4 655\n");
            byte[] frame = a.EncodeRecord(0, msg);
            var result = b.TryDecodeRecord(frame, out byte type, out byte[] data, out _);

            Assert.Equal(SptpsDecodeResult.Ok, result);
            Assert.Equal(0, type);
            Assert.Equal(msg, data);
        }

        [Fact]
        public void Encrypted_SeqnoAdvances_TwoRecords()
        {
            byte[] aToB = Key(1);
            byte[] bToA = Key(100);
            var a = new SptpsRecordLayer();
            var b = new SptpsRecordLayer();
            a.EnableEncryption(aToB, bToA);
            b.EnableEncryption(bToA, aToB);

            byte[] f1 = a.EncodeRecord(0, new byte[] { 1 });
            byte[] f2 = a.EncodeRecord(0, new byte[] { 2 });

            Assert.Equal(SptpsDecodeResult.Ok, b.TryDecodeRecord(f1, out _, out byte[] d1, out _));
            Assert.Equal(SptpsDecodeResult.Ok, b.TryDecodeRecord(f2, out _, out byte[] d2, out _));
            Assert.Equal(new byte[] { 1 }, d1);
            Assert.Equal(new byte[] { 2 }, d2);
        }

        [Fact]
        public void TryDecode_PartialBuffer_NeedMore()
        {
            var send = new SptpsRecordLayer();
            byte[] frame = send.EncodeHandshake(new byte[] { 1, 2, 3, 4, 5 });
            var recv = new SptpsRecordLayer();
            var result = recv.TryDecodeRecord(frame.AsSpan(0, 3), out _, out _, out _);
            Assert.Equal(SptpsDecodeResult.NeedMore, result);
        }

        [Fact]
        public void Encrypted_OutOfOrder_AuthFails()
        {
            byte[] aToB = Key(1);
            byte[] bToA = Key(100);
            var a = new SptpsRecordLayer();
            var b = new SptpsRecordLayer();
            a.EnableEncryption(aToB, bToA);
            b.EnableEncryption(bToA, aToB);

            byte[] f1 = a.EncodeRecord(0, new byte[] { 1 });
            byte[] f2 = a.EncodeRecord(0, new byte[] { 2 });
            // Deliver f2 first: receiver is at inseqno 0 but f2 was sealed under seqno 1 → tag mismatch.
            Assert.Equal(SptpsDecodeResult.AuthFailed, b.TryDecodeRecord(f2, out _, out _, out _));
        }
    }
}
