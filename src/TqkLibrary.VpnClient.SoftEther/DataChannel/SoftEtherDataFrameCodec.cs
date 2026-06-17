using System.Buffers.Binary;
using System.Collections.Generic;

namespace TqkLibrary.VpnClient.SoftEther.DataChannel
{
    /// <summary>
    /// Pure codec for one SoftEther data <b>block</b> — the unit the data session writes to / reads from the TLS byte
    /// stream after login. A block batches one or more raw payloads (Ethernet frames or a keep-alive string):
    /// <c>uint32(num_frames)</c> followed, per frame, by <c>uint32(size) · size bytes</c>. All integers are big-endian.
    /// Re-implemented from the protocol behavior (spec doc <c>07</c>) — not copied from the GPL source. No I/O; the
    /// streaming reader that pulls block bytes off the transport lives in <see cref="SoftEtherDataBlockReader"/>.
    /// </summary>
    public static class SoftEtherDataFrameCodec
    {
        /// <summary>The big-endian <c>uint32</c> count prefix that opens a block (number of frames that follow).</summary>
        public const int CountPrefixLength = 4;

        /// <summary>The big-endian <c>uint32</c> size prefix that opens each frame inside a block.</summary>
        public const int SizePrefixLength = 4;

        /// <summary>
        /// Serializes <paramref name="frames"/> into a single block: the frame count, then each frame length-prefixed.
        /// An empty list still produces a valid block (count 0) — used to send a bare keep-alive batch.
        /// </summary>
        public static byte[] EncodeBlock(IReadOnlyList<ReadOnlyMemory<byte>> frames)
        {
            if (frames is null) throw new ArgumentNullException(nameof(frames));

            int total = CountPrefixLength;
            for (int i = 0; i < frames.Count; i++)
                total += SizePrefixLength + frames[i].Length;

            var block = new byte[total];
            BinaryPrimitives.WriteUInt32BigEndian(block, (uint)frames.Count);
            int pos = CountPrefixLength;
            for (int i = 0; i < frames.Count; i++)
            {
                ReadOnlySpan<byte> frame = frames[i].Span;
                BinaryPrimitives.WriteUInt32BigEndian(block.AsSpan(pos), (uint)frame.Length);
                pos += SizePrefixLength;
                frame.CopyTo(block.AsSpan(pos));
                pos += frame.Length;
            }
            return block;
        }

        /// <summary>Serializes a single frame as a one-frame block (convenience over <see cref="EncodeBlock"/>).</summary>
        public static byte[] EncodeSingle(ReadOnlyMemory<byte> frame)
            => EncodeBlock(new[] { frame });

        /// <summary>
        /// Parses a complete block (as produced by <see cref="EncodeBlock"/>) into its frames. Throws
        /// <see cref="FormatException"/> on a truncated block or a count/size over the
        /// <see cref="SoftEtherDataConstants.MaxFramesPerBlock"/> / <see cref="SoftEtherDataConstants.MaxFrameSize"/> guards.
        /// </summary>
        public static IReadOnlyList<byte[]> DecodeBlock(ReadOnlySpan<byte> block)
        {
            if (block.Length < CountPrefixLength)
                throw new FormatException("SoftEther data block too short for the frame count.");

            uint count = BinaryPrimitives.ReadUInt32BigEndian(block);
            if (count > SoftEtherDataConstants.MaxFramesPerBlock)
                throw new FormatException($"SoftEther data block declares {count} frames, over the {SoftEtherDataConstants.MaxFramesPerBlock} limit.");

            var frames = new List<byte[]>((int)count);
            int pos = CountPrefixLength;
            for (uint i = 0; i < count; i++)
            {
                if (pos + SizePrefixLength > block.Length)
                    throw new FormatException("SoftEther data block truncated at a frame size prefix.");
                uint size = BinaryPrimitives.ReadUInt32BigEndian(block.Slice(pos));
                pos += SizePrefixLength;
                if (size > SoftEtherDataConstants.MaxFrameSize)
                    throw new FormatException($"SoftEther data frame declares {size} bytes, over the {SoftEtherDataConstants.MaxFrameSize} limit.");
                if (pos + (int)size > block.Length)
                    throw new FormatException("SoftEther data block truncated mid-frame.");
                frames.Add(block.Slice(pos, (int)size).ToArray());
                pos += (int)size;
            }
            return frames;
        }

        /// <summary>True if <paramref name="frame"/> is the SoftEther idle keep-alive payload (not an Ethernet frame).</summary>
        public static bool IsKeepAlive(ReadOnlySpan<byte> frame)
            => frame.SequenceEqual(SoftEtherDataConstants.KeepAliveBytes);
    }
}
