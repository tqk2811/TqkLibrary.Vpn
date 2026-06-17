using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;

namespace TqkLibrary.VpnClient.SoftEther.DataChannel
{
    /// <summary>
    /// Per-frame DEFLATE compression for the SoftEther data session (<c>use_compress</c>, negotiated in the
    /// <c>login</c> PACK). When compression is on, each raw payload (Ethernet frame / keep-alive) is compressed
    /// <b>before</b> it is sealed into a data block (<see cref="SoftEtherDataFrameCodec"/>); on the wire a compressed
    /// frame is tagged with the SoftEther 8-byte compression magic <c>0xDEADBEEFCAFEFACE</c> (spec doc <c>07</c>
    /// §"Multi-host &amp; multi-connection") followed by the raw DEFLATE stream (RFC 1951). A frame is only sent
    /// compressed when that actually shrinks it — small/incompressible frames stay raw, so the magic prefix
    /// unambiguously distinguishes the two forms on receive.
    /// <para>
    /// Re-implemented from the protocol behavior (spec doc <c>07</c>) — not copied from the GPL source. Pure codec, no
    /// I/O. <see cref="DeflateStream"/> is used (available on both <c>netstandard2.0</c> and <c>net8.0</c>) so the same
    /// code runs on every TFM. When <c>use_compress</c> and <c>use_encrypt</c> are both on, the frame is compressed
    /// here first and the resulting block bytes are RC4-encrypted by <see cref="SoftEtherEncryptedTransport"/> — the
    /// standard "compress then encrypt" order, since encrypted bytes no longer compress.
    /// </para>
    /// </summary>
    public static class SoftEtherPayloadCompressor
    {
        /// <summary>The SoftEther 8-byte big-endian magic that prefixes a compressed frame (spec doc <c>07</c>).</summary>
        public const ulong CompressionMagic = 0xDEADBEEFCAFEFACEUL;

        /// <summary>The length (bytes) of the <see cref="CompressionMagic"/> prefix.</summary>
        public const int MagicLength = 8;

        /// <summary>
        /// Returns <paramref name="frame"/> in its on-wire form when <c>use_compress</c> is on: DEFLATE-compressed and
        /// magic-prefixed when that is smaller than the raw frame, otherwise the raw frame unchanged (so the codec never
        /// inflates a payload it cannot shrink). The receiver tells the two apart by the magic prefix.
        /// </summary>
        public static byte[] CompressFrame(ReadOnlySpan<byte> frame)
        {
            byte[] deflated = Deflate(frame);
            // Only worth sending compressed if magic + deflate is strictly smaller than the raw frame.
            if (MagicLength + deflated.Length >= frame.Length)
                return frame.ToArray();

            var output = new byte[MagicLength + deflated.Length];
            BinaryPrimitives.WriteUInt64BigEndian(output, CompressionMagic);
            deflated.CopyTo(output.AsSpan(MagicLength));
            return output;
        }

        /// <summary>
        /// Reverses <see cref="CompressFrame"/>: if <paramref name="frame"/> begins with the <see cref="CompressionMagic"/>
        /// it is inflated back to the original payload; otherwise it is returned unchanged (it was sent raw). Throws
        /// <see cref="FormatException"/> if a magic-tagged frame carries a corrupt DEFLATE stream or inflates past
        /// <see cref="SoftEtherDataConstants.MaxFrameSize"/>.
        /// </summary>
        public static byte[] DecompressFrame(ReadOnlySpan<byte> frame)
        {
            if (!StartsWithMagic(frame))
                return frame.ToArray();
            return Inflate(frame.Slice(MagicLength));
        }

        /// <summary>True if <paramref name="frame"/> is a compressed frame (begins with <see cref="CompressionMagic"/>).</summary>
        public static bool IsCompressed(ReadOnlySpan<byte> frame) => StartsWithMagic(frame);

        static bool StartsWithMagic(ReadOnlySpan<byte> frame)
            => frame.Length >= MagicLength && BinaryPrimitives.ReadUInt64BigEndian(frame) == CompressionMagic;

        static byte[] Deflate(ReadOnlySpan<byte> data)
        {
            using var output = new MemoryStream();
            using (var deflate = new DeflateStream(output, CompressionMode.Compress, leaveOpen: true))
            {
                byte[] buffer = data.ToArray();
                deflate.Write(buffer, 0, buffer.Length);
            }
            return output.ToArray();
        }

        static byte[] Inflate(ReadOnlySpan<byte> compressed)
        {
            try
            {
                using var input = new MemoryStream(compressed.ToArray(), writable: false);
                using var deflate = new DeflateStream(input, CompressionMode.Decompress);
                using var output = new MemoryStream();
                byte[] buffer = new byte[4096];
                int read;
                while ((read = deflate.Read(buffer, 0, buffer.Length)) > 0)
                {
                    output.Write(buffer, 0, read);
                    if (output.Length > SoftEtherDataConstants.MaxFrameSize)
                        throw new FormatException(
                            $"SoftEther compressed frame inflates past the {SoftEtherDataConstants.MaxFrameSize}-byte limit.");
                }
                return output.ToArray();
            }
            catch (InvalidDataException ex)
            {
                throw new FormatException("SoftEther compressed frame carries a corrupt DEFLATE stream.", ex);
            }
        }
    }
}
