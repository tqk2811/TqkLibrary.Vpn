using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.SoftEther.DataChannel;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.SoftEther.Tests
{
    /// <summary>
    /// Offline tests for the SoftEther data-block codec (the Ethernet-over-TLS framing): block round-trip (single and
    /// multi-frame), keep-alive recognition, over-size/truncation guards, and the streaming block reader reassembling a
    /// block across partial transport reads. No network, no Integration trait.
    /// </summary>
    public class SoftEtherDataFrameCodecTests
    {
        [Fact]
        public void EncodeDecode_MultiFrameBlock_RoundTrips()
        {
            var frames = new List<ReadOnlyMemory<byte>>
            {
                new byte[] { 1, 2, 3 },
                Array.Empty<byte>(),
                new byte[] { 9, 8, 7, 6, 5 },
            };
            byte[] block = SoftEtherDataFrameCodec.EncodeBlock(frames);

            // First 4 bytes = big-endian frame count.
            Assert.Equal(3u, BinaryPrimitives.ReadUInt32BigEndian(block));

            IReadOnlyList<byte[]> decoded = SoftEtherDataFrameCodec.DecodeBlock(block);
            Assert.Equal(3, decoded.Count);
            Assert.Equal(new byte[] { 1, 2, 3 }, decoded[0]);
            Assert.Empty(decoded[1]);
            Assert.Equal(new byte[] { 9, 8, 7, 6, 5 }, decoded[2]);
        }

        [Fact]
        public void EncodeSingle_IsOneFrameBlock()
        {
            byte[] frame = { 0xAA, 0xBB, 0xCC };
            byte[] block = SoftEtherDataFrameCodec.EncodeSingle(frame);
            IReadOnlyList<byte[]> decoded = SoftEtherDataFrameCodec.DecodeBlock(block);
            Assert.Equal(frame, Assert.Single(decoded));
        }

        [Fact]
        public void KeepAlive_IsRecognised()
        {
            Assert.True(SoftEtherDataFrameCodec.IsKeepAlive(SoftEtherDataConstants.KeepAliveBytes));
            Assert.False(SoftEtherDataFrameCodec.IsKeepAlive(new byte[] { 1, 2, 3 }));
            Assert.Equal("Internet Connection Keep Alive Packet", SoftEtherDataConstants.KeepAliveText);
        }

        [Fact]
        public void DecodeBlock_RejectsTruncatedOrOverSized()
        {
            Assert.Throws<FormatException>(() => SoftEtherDataFrameCodec.DecodeBlock(new byte[] { 0, 0 }));

            // Declares 1 frame of 10 bytes but only 2 follow.
            byte[] truncated = new byte[4 + 4 + 2];
            BinaryPrimitives.WriteUInt32BigEndian(truncated, 1u);
            BinaryPrimitives.WriteUInt32BigEndian(truncated.AsSpan(4), 10u);
            Assert.Throws<FormatException>(() => SoftEtherDataFrameCodec.DecodeBlock(truncated));

            // Declares an absurd frame count.
            byte[] hugeCount = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(hugeCount, uint.MaxValue);
            Assert.Throws<FormatException>(() => SoftEtherDataFrameCodec.DecodeBlock(hugeCount));
        }

        [Fact]
        public async Task BlockReader_ReassemblesAcrossPartialReads()
        {
            var frames = new List<ReadOnlyMemory<byte>>
            {
                new byte[] { 10, 11, 12, 13 },
                new byte[] { 20, 21 },
            };
            byte[] block = SoftEtherDataFrameCodec.EncodeBlock(frames);

            // A transport that yields the block one byte at a time (worst-case fragmentation), then EOF.
            var transport = new DripTransport(block);
            var reader = new SoftEtherDataBlockReader(transport);

            IReadOnlyList<byte[]> read = await reader.ReadBlockAsync(CancellationToken.None);
            Assert.Equal(2, read.Count);
            Assert.Equal(new byte[] { 10, 11, 12, 13 }, read[0]);
            Assert.Equal(new byte[] { 20, 21 }, read[1]);

            // Next read sees a clean EOF at a block boundary → empty result.
            Assert.Empty(await reader.ReadBlockAsync(CancellationToken.None));
        }

        /// <summary>An <see cref="Abstractions.Transport.Interfaces.IByteStreamTransport"/> that drips one byte per read, then EOF.</summary>
        sealed class DripTransport : Abstractions.Transport.Interfaces.IByteStreamTransport
        {
            readonly byte[] _data;
            int _pos;
            public DripTransport(byte[] data) => _data = data;

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

            public ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                if (_pos >= _data.Length || buffer.Length == 0) return new ValueTask<int>(0);
                buffer.Span[0] = _data[_pos++];
                return new ValueTask<int>(1);
            }

            public ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) => default;
            public ValueTask DisposeAsync() => default;
        }
    }
}
