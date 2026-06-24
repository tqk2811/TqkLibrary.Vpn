using System.Collections.Generic;
using System.IO;
using System.Text;

namespace TqkLibrary.VpnClient.Ssh.Wire
{
    /// <summary>
    /// Writes the SSH wire data types (RFC 4251 §5) onto a growable buffer: <c>byte</c>, <c>boolean</c>,
    /// <c>uint32</c>/<c>uint64</c> (network byte order), <c>string</c> (a uint32 length prefix + the raw bytes — used for
    /// both text and binary blobs), <c>mpint</c> (a two's-complement big-endian integer, a leading <c>0x00</c> added when
    /// the high bit is set so the value reads as non-negative) and <c>name-list</c> (a comma-joined ASCII string).
    /// All multi-byte integers are big-endian. Not thread-safe; one writer builds one message.
    /// </summary>
    public sealed class SshWriter
    {
        readonly MemoryStream _buffer;

        /// <summary>Creates an empty writer.</summary>
        public SshWriter() => _buffer = new MemoryStream();

        /// <summary>The bytes written so far (a fresh array).</summary>
        public byte[] ToArray() => _buffer.ToArray();

        /// <summary>The number of bytes written so far.</summary>
        public int Length => (int)_buffer.Length;

        /// <summary>Writes a single byte.</summary>
        public SshWriter WriteByte(byte value)
        {
            _buffer.WriteByte(value);
            return this;
        }

        /// <summary>Writes a boolean (0 = false, 1 = true).</summary>
        public SshWriter WriteBoolean(bool value) => WriteByte((byte)(value ? 1 : 0));

        /// <summary>Writes a uint32 in network byte order (big-endian).</summary>
        public SshWriter WriteUInt32(uint value)
        {
            _buffer.WriteByte((byte)(value >> 24));
            _buffer.WriteByte((byte)(value >> 16));
            _buffer.WriteByte((byte)(value >> 8));
            _buffer.WriteByte((byte)value);
            return this;
        }

        /// <summary>Writes a uint64 in network byte order (big-endian).</summary>
        public SshWriter WriteUInt64(ulong value)
        {
            for (int i = 7; i >= 0; i--) _buffer.WriteByte((byte)(value >> (8 * i)));
            return this;
        }

        /// <summary>Writes raw bytes verbatim (no length prefix).</summary>
        public SshWriter WriteRaw(ReadOnlySpan<byte> value)
        {
#if NET5_0_OR_GREATER
            _buffer.Write(value);
#else
            byte[] tmp = value.ToArray();
            _buffer.Write(tmp, 0, tmp.Length);
#endif
            return this;
        }

        /// <summary>Writes an SSH <c>string</c>: a uint32 length prefix followed by the bytes (binary-safe).</summary>
        public SshWriter WriteString(ReadOnlySpan<byte> value)
        {
            WriteUInt32((uint)value.Length);
            return WriteRaw(value);
        }

        /// <summary>Writes an SSH <c>string</c> from ASCII/UTF-8 text (length prefix + bytes).</summary>
        public SshWriter WriteString(string value) => WriteString(Encoding.UTF8.GetBytes(value ?? string.Empty));

        /// <summary>
        /// Writes an SSH <c>mpint</c> (RFC 4251 §5): the value <paramref name="magnitude"/> is a big-endian unsigned
        /// integer; it is emitted as a two's-complement signed number, so a leading <c>0x00</c> is added when the most
        /// significant bit of the first non-zero byte is set, and leading zero bytes are trimmed. Zero is the empty string.
        /// </summary>
        public SshWriter WriteMpint(ReadOnlySpan<byte> magnitude)
        {
            // Trim leading zero bytes.
            int start = 0;
            while (start < magnitude.Length && magnitude[start] == 0) start++;
            if (start == magnitude.Length)
            {
                WriteUInt32(0); // value zero → empty mpint
                return this;
            }

            bool needPad = (magnitude[start] & 0x80) != 0; // high bit set → prepend 0x00 to keep it non-negative
            int len = magnitude.Length - start + (needPad ? 1 : 0);
            WriteUInt32((uint)len);
            if (needPad) _buffer.WriteByte(0);
            return WriteRaw(magnitude.Slice(start));
        }

        /// <summary>Writes an SSH <c>name-list</c> (RFC 4251 §5): the names comma-joined as one ASCII <c>string</c>.</summary>
        public SshWriter WriteNameList(IReadOnlyList<string> names)
        {
            string joined = names is null || names.Count == 0 ? string.Empty : string.Join(",", names);
            return WriteString(Encoding.ASCII.GetBytes(joined));
        }
    }
}
