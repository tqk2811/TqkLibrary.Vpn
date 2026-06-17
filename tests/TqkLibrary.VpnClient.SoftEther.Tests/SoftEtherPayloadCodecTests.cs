using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.SoftEther.DataChannel;
using Xunit;

namespace TqkLibrary.VpnClient.SoftEther.Tests
{
    /// <summary>
    /// Offline tests for the SoftEther data-session payload codecs (V.4 <c>use_compress</c> / <c>use_encrypt</c>):
    /// per-frame DEFLATE compression (<see cref="SoftEtherPayloadCompressor"/>), the per-direction RC4 transport layer
    /// (<see cref="SoftEtherEncryptedTransport"/>, reusing <c>Crypto.Rc4</c>), and the combined block round-trip through
    /// the <see cref="SoftEtherEthernetChannel"/>. All self-interop over an in-memory pipe — no network, no Integration trait.
    /// </summary>
    public class SoftEtherPayloadCodecTests
    {
        // ---- per-frame DEFLATE compression -----------------------------------------------------------

        [Fact]
        public void Compressor_CompressibleFrame_TagsWithMagicAndRoundTrips()
        {
            // A highly compressible frame (long run) should come back smaller with the magic prefix.
            byte[] frame = Enumerable.Repeat((byte)0xAB, 1500).ToArray();
            byte[] wire = SoftEtherPayloadCompressor.CompressFrame(frame);

            Assert.True(SoftEtherPayloadCompressor.IsCompressed(wire));
            Assert.True(wire.Length < frame.Length);
            Assert.Equal(frame, SoftEtherPayloadCompressor.DecompressFrame(wire));
        }

        [Fact]
        public void Compressor_IncompressibleFrame_StaysRaw()
        {
            // Random bytes do not shrink → sent raw (no magic), decompress is identity.
            var rng = new Random(7);
            byte[] frame = new byte[64];
            rng.NextBytes(frame);
            byte[] wire = SoftEtherPayloadCompressor.CompressFrame(frame);

            Assert.False(SoftEtherPayloadCompressor.IsCompressed(wire));
            Assert.Equal(frame, wire);
            Assert.Equal(frame, SoftEtherPayloadCompressor.DecompressFrame(wire));
        }

        [Fact]
        public void Compressor_RawFrameWithoutMagic_DecompressesToItself()
        {
            byte[] frame = { 1, 2, 3, 4, 5 };
            Assert.False(SoftEtherPayloadCompressor.IsCompressed(frame));
            Assert.Equal(frame, SoftEtherPayloadCompressor.DecompressFrame(frame));
        }

        [Fact]
        public void Compressor_CorruptDeflateAfterMagic_Throws()
        {
            // Magic prefix but an invalid DEFLATE body must surface as FormatException, not a hard crash. A first byte of
            // 0x07 sets BTYPE=11 (the reserved/invalid block type in RFC 1951 §3.2.3) → DeflateStream errors immediately.
            byte[] bad = new byte[SoftEtherPayloadCompressor.MagicLength + 3];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(bad, SoftEtherPayloadCompressor.CompressionMagic);
            bad[SoftEtherPayloadCompressor.MagicLength] = 0x07;   // BFINAL=1, BTYPE=11 (reserved) → invalid
            bad[SoftEtherPayloadCompressor.MagicLength + 1] = 0xFF;
            bad[SoftEtherPayloadCompressor.MagicLength + 2] = 0xFF;
            Assert.Throws<FormatException>(() => SoftEtherPayloadCompressor.DecompressFrame(bad));
        }

        // ---- per-direction RC4 transport (use_encrypt) -----------------------------------------------

        [Fact]
        public void EncryptedTransport_DeriveDirectionKeys_AreDistinctAndLabelled()
        {
            byte[] sessionKey = SessionKey();
            (byte[] c2s, byte[] s2c) = SoftEtherEncryptedTransport.DeriveDirectionKeys(sessionKey);

            Assert.NotEqual(c2s, s2c);                       // each direction has its own keystream
            Assert.Equal(sessionKey.Length + 1, c2s.Length);  // session key + 1-byte label
            Assert.Equal((byte)0x01, c2s[c2s.Length - 1]);
            Assert.Equal((byte)0x02, s2c[s2c.Length - 1]);
        }

        [Fact]
        public void EncryptedTransport_RejectsEmptySessionKey()
            => Assert.Throws<ArgumentException>(() => SoftEtherEncryptedTransport.DeriveDirectionKeys(Array.Empty<byte>()));

        [Fact]
        public async Task EncryptedTransport_ClientServerMirror_RoundTripsBothDirections()
        {
            // Two mirror-symmetric ends over a loopback pipe: what the client encrypts the server decrypts and vice-versa.
            byte[] sessionKey = SessionKey();
            var (rawClient, rawServer) = DuplexPipe.CreatePair();
            IByteStreamTransport client = SoftEtherEncryptedTransport.CreateClient(rawClient, sessionKey);
            IByteStreamTransport server = SoftEtherEncryptedTransport.CreateServer(rawServer, sessionKey);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

            // client → server, multiple writes (RC4 keystream advances continuously across writes).
            byte[] m1 = { 10, 20, 30 };
            byte[] m2 = Enumerable.Range(0, 200).Select(i => (byte)i).ToArray();
            await client.WriteAsync(m1, cts.Token);
            await client.WriteAsync(m2, cts.Token);
            Assert.Equal(m1, await ReadExactlyAsync(server, m1.Length, cts.Token));
            Assert.Equal(m2, await ReadExactlyAsync(server, m2.Length, cts.Token));

            // server → client, independent keystream.
            byte[] m3 = { 0xDE, 0xAD, 0xBE, 0xEF };
            await server.WriteAsync(m3, cts.Token);
            Assert.Equal(m3, await ReadExactlyAsync(client, m3.Length, cts.Token));

            await client.DisposeAsync();
            await server.DisposeAsync();
        }

        [Fact]
        public async Task EncryptedTransport_CiphertextOnTheWireIsNotPlaintext()
        {
            // The raw pipe must carry ciphertext, not the original bytes (proves RC4 is actually applied).
            byte[] sessionKey = SessionKey();
            var (rawClient, rawServer) = DuplexPipe.CreatePair();
            IByteStreamTransport client = SoftEtherEncryptedTransport.CreateClient(rawClient, sessionKey);

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            byte[] plaintext = Enumerable.Repeat((byte)0x00, 32).ToArray();   // zeros → ciphertext = raw RC4 keystream
            await client.WriteAsync(plaintext, cts.Token);

            byte[] onWire = await ReadExactlyAsync(rawServer, plaintext.Length, cts.Token);  // read the unwrapped pipe
            Assert.NotEqual(plaintext, onWire);

            await client.DisposeAsync();
        }

        // ---- combined: block round-trip through the channel (compress + encrypt) ---------------------

        [Theory]
        [InlineData(false, false)]
        [InlineData(true, false)]
        [InlineData(false, true)]
        [InlineData(true, true)]
        public async Task DataSession_RoundTripsFrame_AcrossCompressAndEncryptCombinations(bool useCompress, bool useEncrypt)
        {
            byte[] sessionKey = SessionKey();
            var (rawClient, rawServer) = DuplexPipe.CreatePair();
            IByteStreamTransport clientTransport = useEncrypt
                ? SoftEtherEncryptedTransport.CreateClient(rawClient, sessionKey)
                : rawClient;
            IByteStreamTransport serverTransport = useEncrypt
                ? SoftEtherEncryptedTransport.CreateServer(rawServer, sessionKey)
                : rawServer;

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

            // A realistic (compressible) Ethernet frame: 14-byte header + a long zero-ish payload.
            byte[] ethernetFrame = BuildEthernetFrame(payloadLength: 1000);

            // Client side: a channel that compresses (or not) and writes a block to the encrypted (or raw) transport.
            var clientChannel = new SoftEtherEthernetChannel(
                Mac(0x02), (block, ct) => clientTransport.WriteAsync(block, ct), mtu: 1500, useCompress: useCompress);
            await clientChannel.WriteFrameAsync(ethernetFrame, cts.Token);

            // Server side: decode the block off its transport, then a channel decompresses (or not) and surfaces it.
            var serverReader = new SoftEtherDataBlockReader(serverTransport);
            IReadOnlyList<byte[]> frames = await serverReader.ReadBlockAsync(cts.Token);
            Assert.Single(frames);

            byte[]? delivered = null;
            var serverChannel = new SoftEtherEthernetChannel(
                Mac(0x06), (_, _) => default, mtu: 1500, useCompress: useCompress);
            serverChannel.InboundFrame += f => delivered = f.ToArray();
            serverChannel.Deliver(frames[0]);

            Assert.Equal(ethernetFrame, delivered);

            // When compress is on the frame must actually have been compressed on the wire (magic prefix present).
            Assert.Equal(useCompress, SoftEtherPayloadCompressor.IsCompressed(frames[0]));

            await clientChannel.DisposeAsync();
            await serverChannel.DisposeAsync();
            await clientTransport.DisposeAsync();
            await serverTransport.DisposeAsync();
        }

        // ---- helpers ---------------------------------------------------------------------------------

        static byte[] SessionKey(byte start = 0xA0)
        {
            var k = new byte[SoftEtherProtocol.RandomSize];
            for (int i = 0; i < k.Length; i++) k[i] = (byte)(start + i);
            return k;
        }

        static byte[] Mac(byte first)
        {
            var mac = new byte[6];
            mac[0] = first;
            mac[5] = 0x01;
            return mac;
        }

        // A minimal Ethernet frame: dst MAC + src MAC + ethertype (IPv4) + a compressible payload.
        static byte[] BuildEthernetFrame(int payloadLength)
        {
            var frame = new byte[14 + payloadLength];
            for (int i = 0; i < 6; i++) frame[i] = 0x06;        // dst
            for (int i = 6; i < 12; i++) frame[i] = 0x02;       // src
            frame[12] = 0x08; frame[13] = 0x00;                 // ethertype IPv4
            for (int i = 0; i < payloadLength; i++) frame[14 + i] = (byte)(i % 7);  // compressible pattern
            return frame;
        }

        static async Task<byte[]> ReadExactlyAsync(IByteStreamTransport transport, int count, CancellationToken token)
        {
            var buffer = new byte[count];
            int filled = 0;
            while (filled < count)
            {
                int read = await transport.ReadAsync(new Memory<byte>(buffer, filled, count - filled), token);
                if (read == 0) throw new InvalidOperationException("unexpected EOF in test");
                filled += read;
            }
            return buffer;
        }
    }
}
