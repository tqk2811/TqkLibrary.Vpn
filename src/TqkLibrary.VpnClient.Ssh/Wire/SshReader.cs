using System.Text;

namespace TqkLibrary.VpnClient.Ssh.Wire
{
    /// <summary>
    /// Reads the SSH wire data types (RFC 4251 §5) from a byte buffer with a moving cursor — the inverse of
    /// <see cref="SshWriter"/>: <c>byte</c>, <c>boolean</c>, <c>uint32</c>/<c>uint64</c> (big-endian), <c>string</c>
    /// (length-prefixed bytes), <c>mpint</c> (returned as the magnitude bytes, leading sign/zero padding trimmed) and
    /// <c>name-list</c>. A read past the end throws <see cref="EndOfStreamException"/> — a malformed peer message surfaces
    /// as that rather than an out-of-range index. Not thread-safe.
    /// </summary>
    public ref struct SshReader
    {
        readonly ReadOnlySpan<byte> _data;
        int _pos;

        /// <summary>Wraps a buffer for reading from offset 0.</summary>
        public SshReader(ReadOnlySpan<byte> data)
        {
            _data = data;
            _pos = 0;
        }

        /// <summary>The current read offset.</summary>
        public int Position => _pos;

        /// <summary>The number of bytes not yet consumed.</summary>
        public int Remaining => _data.Length - _pos;

        /// <summary>Reads a single byte.</summary>
        public byte ReadByte()
        {
            if (_pos + 1 > _data.Length) throw new EndOfStreamException("SSH reader: byte past end.");
            return _data[_pos++];
        }

        /// <summary>Reads a boolean (any non-zero byte is true).</summary>
        public bool ReadBoolean() => ReadByte() != 0;

        /// <summary>Reads a uint32 (big-endian).</summary>
        public uint ReadUInt32()
        {
            if (_pos + 4 > _data.Length) throw new EndOfStreamException("SSH reader: uint32 past end.");
            uint v = (uint)((_data[_pos] << 24) | (_data[_pos + 1] << 16) | (_data[_pos + 2] << 8) | _data[_pos + 3]);
            _pos += 4;
            return v;
        }

        /// <summary>Reads a uint64 (big-endian).</summary>
        public ulong ReadUInt64()
        {
            if (_pos + 8 > _data.Length) throw new EndOfStreamException("SSH reader: uint64 past end.");
            ulong v = 0;
            for (int i = 0; i < 8; i++) v = (v << 8) | _data[_pos + i];
            _pos += 8;
            return v;
        }

        /// <summary>Reads an SSH <c>string</c> and returns its bytes (a slice into the underlying buffer — copy if it must outlive this reader).</summary>
        public ReadOnlySpan<byte> ReadString()
        {
            uint len = ReadUInt32();
            if (_pos + len > _data.Length) throw new EndOfStreamException("SSH reader: string past end.");
            ReadOnlySpan<byte> slice = _data.Slice(_pos, (int)len);
            _pos += (int)len;
            return slice;
        }

        /// <summary>Reads an SSH <c>string</c> as a fresh byte array.</summary>
        public byte[] ReadStringBytes() => ReadString().ToArray();

        /// <summary>Reads an SSH <c>string</c> decoded as UTF-8 text.</summary>
        public string ReadStringUtf8()
        {
            ReadOnlySpan<byte> s = ReadString();
#if NET5_0_OR_GREATER
            return Encoding.UTF8.GetString(s);
#else
            return Encoding.UTF8.GetString(s.ToArray());
#endif
        }

        /// <summary>Reads an SSH <c>mpint</c> and returns the magnitude bytes (sign/leading-zero padding removed).</summary>
        public byte[] ReadMpint()
        {
            ReadOnlySpan<byte> s = ReadString();
            int start = 0;
            while (start < s.Length && s[start] == 0) start++; // drop the sign byte / leading zeros
            return s.Slice(start).ToArray();
        }

        /// <summary>Reads an SSH <c>name-list</c> (comma-separated ASCII names). An empty list yields an empty array.</summary>
        public string[] ReadNameList()
        {
            ReadOnlySpan<byte> s = ReadString();
            if (s.Length == 0) return Array.Empty<string>();
#if NET5_0_OR_GREATER
            string joined = Encoding.ASCII.GetString(s);
#else
            string joined = Encoding.ASCII.GetString(s.ToArray());
#endif
            return joined.Split(',');
        }

        /// <summary>Reads <paramref name="count"/> raw bytes (a slice into the underlying buffer).</summary>
        public ReadOnlySpan<byte> ReadRaw(int count)
        {
            if (_pos + count > _data.Length) throw new EndOfStreamException("SSH reader: raw read past end.");
            ReadOnlySpan<byte> slice = _data.Slice(_pos, count);
            _pos += count;
            return slice;
        }

        /// <summary>The remaining bytes (a slice into the underlying buffer).</summary>
        public ReadOnlySpan<byte> ReadToEnd()
        {
            ReadOnlySpan<byte> slice = _data.Slice(_pos);
            _pos = _data.Length;
            return slice;
        }
    }
}
