using TqkLibrary.VpnClient.N2n;
using TqkLibrary.VpnClient.N2n.Transform;
using TqkLibrary.VpnClient.N2n.Wire.Enums;
using TqkLibrary.VpnClient.N2n.Wire.Models;
using Xunit;

namespace TqkLibrary.VpnClient.N2n.Tests
{
    /// <summary>
    /// PACKET (data-plane) tests: the NULL and AES transforms round-trip the inner Ethernet frame, and a full PACKET
    /// message encodes and decodes both directions (A→B and B→A) with the same shared key — the self-pair check that a
    /// live run still has to confirm against a real edge, but that locks the data-plane framing here.
    /// </summary>
    public class N2nPacketTransformTests
    {
        readonly N2nPacketCodec _codec = new N2nPacketCodec();
        const string Community = "labnet";

        static byte[] Mac(byte last) => new byte[] { 0x02, 0x00, 0x00, 0x00, 0x00, last };

        // A small but realistic Ethernet frame: dst(6) src(6) ethertype(2 = IPv4) + 20-byte IP-ish body.
        static byte[] SampleFrame()
        {
            byte[] f = new byte[34];
            Mac(0xBB).CopyTo(f, 0);
            Mac(0xAA).CopyTo(f, 6);
            f[12] = 0x08; f[13] = 0x00; // IPv4
            for (int i = 14; i < f.Length; i++) f[i] = (byte)(i * 7);
            return f;
        }

        [Fact]
        public void NullTransform_IsIdentity()
        {
            var t = new N2nNullTransform();
            byte[] frame = SampleFrame();
            byte[] enc = t.Encode(frame);
            Assert.Equal(frame, enc);
            Assert.Equal(frame, t.Decode(enc));
            Assert.Equal(N2nTransformId.Null, t.Id);
        }

        [Theory]
        [InlineData(16)]
        [InlineData(24)]
        [InlineData(32)]
        public void AesTransform_RoundTrips_AllKeySizes(int keyLen)
        {
            byte[] key = new byte[keyLen];
            for (int i = 0; i < keyLen; i++) key[i] = (byte)(i + 1);
            var t = new N2nAesTransform(key);
            byte[] frame = SampleFrame();

            byte[] enc = t.Encode(frame);
            // Output is a multiple of the AES block and longer than frame (16-byte preamble + padding).
            Assert.Equal(0, enc.Length % 16);
            Assert.True(enc.Length >= frame.Length + N2nAesTransform.PreambleSize);

            byte[] dec = t.Decode(enc);
            // Decode drops the preamble; the frame is a prefix of the (possibly zero-padded) result.
            Assert.True(dec.Length >= frame.Length);
            Assert.True(dec.AsSpan(0, frame.Length).SequenceEqual(frame));
        }

        [Fact]
        public void AesTransform_DifferentPreamble_ProducesDifferentCiphertext()
        {
            byte[] key = new byte[32];
            var t = new N2nAesTransform(key);
            byte[] frame = SampleFrame();
            byte[] a = t.Encode(frame);
            byte[] b = t.Encode(frame);
            // Random preamble => CBC chains differently => ciphertext differs even for identical plaintext.
            Assert.False(a.AsSpan().SequenceEqual(b));
            // Both still decrypt back to the frame.
            Assert.True(t.Decode(a).AsSpan(0, frame.Length).SequenceEqual(frame));
            Assert.True(t.Decode(b).AsSpan(0, frame.Length).SequenceEqual(frame));
        }

        [Fact]
        public void Packet_NullTransform_RoundTrips_BothDirections()
        {
            var transform = new N2nNullTransform();
            byte[] frame = SampleFrame();

            // A -> B
            var ab = new N2nPacket { SrcMac = Mac(0xAA), DstMac = Mac(0xBB), Payload = frame, Transform = N2nTransformId.Null };
            byte[] pktAb = _codec.EncodePacket(Community, ab, transform);
            Assert.True(_codec.TryDecodePacket(pktAb, transform, out var hAb, out var gotAb));
            Assert.Equal(N2nPacketType.Packet, hAb.PacketType);
            Assert.Equal(ab.SrcMac, gotAb.SrcMac);
            Assert.Equal(ab.DstMac, gotAb.DstMac);
            Assert.Equal(frame, gotAb.Payload);
            Assert.Equal(N2nTransformId.Null, gotAb.Transform);

            // B -> A
            var ba = new N2nPacket { SrcMac = Mac(0xBB), DstMac = Mac(0xAA), Payload = frame, Transform = N2nTransformId.Null };
            byte[] pktBa = _codec.EncodePacket(Community, ba, transform);
            Assert.True(_codec.TryDecodePacket(pktBa, transform, out _, out var gotBa));
            Assert.Equal(frame, gotBa.Payload);
            Assert.Equal(ba.SrcMac, gotBa.SrcMac);
        }

        [Fact]
        public void Packet_AesTransform_RoundTrips_BothDirections_SameKey()
        {
            byte[] key = new byte[32];
            for (int i = 0; i < 32; i++) key[i] = (byte)(0x40 + i);
            var transform = new N2nAesTransform(key);
            byte[] frame = SampleFrame();

            var ab = new N2nPacket { SrcMac = Mac(0xAA), DstMac = Mac(0xBB), Payload = frame, Transform = N2nTransformId.Aes };
            byte[] pktAb = _codec.EncodePacket(Community, ab, transform);
            Assert.True(_codec.TryDecodePacket(pktAb, transform, out _, out var gotAb));
            Assert.Equal(N2nTransformId.Aes, gotAb.Transform);
            Assert.True(gotAb.Payload.AsSpan(0, frame.Length).SequenceEqual(frame));

            var ba = new N2nPacket { SrcMac = Mac(0xBB), DstMac = Mac(0xAA), Payload = frame, Transform = N2nTransformId.Aes };
            byte[] pktBa = _codec.EncodePacket(Community, ba, transform);
            Assert.True(_codec.TryDecodePacket(pktBa, transform, out _, out var gotBa));
            Assert.True(gotBa.Payload.AsSpan(0, frame.Length).SequenceEqual(frame));
        }

        [Fact]
        public void Packet_TransformIdStampedInBody()
        {
            byte[] key = new byte[16];
            var transform = new N2nAesTransform(key);
            var pkt = new N2nPacket { SrcMac = Mac(1), DstMac = Mac(2), Payload = SampleFrame() };
            byte[] wire = _codec.EncodePacket(Community, pkt, transform);
            // body: common(24) + src(6) + dst(6) + compression(1) + transform(1)
            int transformByteOffset = 24 + 6 + 6 + 1;
            Assert.Equal((byte)N2nTransformId.Aes, wire[transformByteOffset]);
        }

        [Fact]
        public void AesTransform_RejectsBadKeyLength()
        {
            Assert.Throws<ArgumentException>(() => new N2nAesTransform(new byte[20]));
        }
    }
}
