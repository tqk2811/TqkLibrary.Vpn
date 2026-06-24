namespace TqkLibrary.VpnClient.Nebula.Certificate
{
    /// <summary>
    /// A minimal forward-only protobuf wire-format reader (the subset Nebula's certificate / handshake messages use:
    /// varint, length-delimited, and packed repeated varints). Written from the protobuf encoding spec — Nebula's
    /// <c>cert.proto</c> only needs these three wire types. Not a general-purpose protobuf library.
    /// </summary>
    public ref struct ProtobufReader
    {
        readonly ReadOnlySpan<byte> _data;
        int _pos;

        /// <summary>Wraps <paramref name="data"/> for sequential field reads from offset 0.</summary>
        public ProtobufReader(ReadOnlySpan<byte> data)
        {
            _data = data;
            _pos = 0;
        }

        /// <summary>Whether there are more bytes to read.</summary>
        public bool HasMore => _pos < _data.Length;

        /// <summary>
        /// Reads the next field tag, exposing its <paramref name="fieldNumber"/> and <paramref name="wireType"/>
        /// (0 = varint, 2 = length-delimited). Returns false at end of input.
        /// </summary>
        public bool TryReadTag(out int fieldNumber, out int wireType)
        {
            fieldNumber = 0;
            wireType = 0;
            if (!HasMore) return false;
            ulong tag = ReadVarint();
            fieldNumber = (int)(tag >> 3);
            wireType = (int)(tag & 0x7);
            return true;
        }

        /// <summary>Reads a base-128 varint (LEB128, little-endian groups).</summary>
        public ulong ReadVarint()
        {
            ulong result = 0;
            int shift = 0;
            while (true)
            {
                if (_pos >= _data.Length) throw new FormatException("Truncated protobuf varint.");
                byte b = _data[_pos++];
                result |= (ulong)(b & 0x7F) << shift;
                if ((b & 0x80) == 0) break;
                shift += 7;
                if (shift >= 64) throw new FormatException("Protobuf varint too long.");
            }
            return result;
        }

        /// <summary>Reads a length-delimited field's bytes (a length varint followed by that many bytes).</summary>
        public ReadOnlySpan<byte> ReadLengthDelimited()
        {
            int len = checked((int)ReadVarint());
            if (_pos + len > _data.Length) throw new FormatException("Truncated protobuf length-delimited field.");
            ReadOnlySpan<byte> slice = _data.Slice(_pos, len);
            _pos += len;
            return slice;
        }

        /// <summary>Skips a field of the given <paramref name="wireType"/> (used for unknown fields).</summary>
        public void SkipField(int wireType)
        {
            switch (wireType)
            {
                case 0: ReadVarint(); break;                 // varint
                case 2: ReadLengthDelimited(); break;        // length-delimited
                case 1: Advance(8); break;                   // 64-bit
                case 5: Advance(4); break;                   // 32-bit
                default: throw new FormatException($"Unsupported protobuf wire type {wireType}.");
            }
        }

        void Advance(int count)
        {
            if (_pos + count > _data.Length) throw new FormatException("Truncated protobuf fixed-width field.");
            _pos += count;
        }
    }
}
