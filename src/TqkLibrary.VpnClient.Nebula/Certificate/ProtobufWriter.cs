namespace TqkLibrary.VpnClient.Nebula.Certificate
{
    /// <summary>
    /// A minimal append-only protobuf wire-format writer (the subset Nebula's certificate / handshake messages use:
    /// varint, length-delimited, and packed repeated varints). Produces byte-identical output to the canonical
    /// protobuf encoding for the fields written, in ascending field-number order — required so that re-marshalling a
    /// certificate's details reproduces exactly the bytes the CA signed (Nebula signs <c>Marshal(Details)</c>).
    /// </summary>
    public sealed class ProtobufWriter
    {
        readonly List<byte> _buffer = new();

        /// <summary>The bytes written so far.</summary>
        public byte[] ToArray() => _buffer.ToArray();

        /// <summary>Writes a varint field tag (<c>fieldNumber &lt;&lt; 3 | wireType</c>).</summary>
        void WriteTag(int fieldNumber, int wireType) => WriteVarint(((ulong)(uint)fieldNumber << 3) | (uint)wireType);

        /// <summary>Appends a base-128 varint (LEB128).</summary>
        public void WriteVarint(ulong value)
        {
            while (value >= 0x80)
            {
                _buffer.Add((byte)(value | 0x80));
                value >>= 7;
            }
            _buffer.Add((byte)value);
        }

        /// <summary>Writes a varint field (wire type 0).</summary>
        public void WriteVarintField(int fieldNumber, ulong value)
        {
            WriteTag(fieldNumber, 0);
            WriteVarint(value);
        }

        /// <summary>Writes a signed varint field as protobuf <c>int64</c>/<c>int32</c> (two's-complement, not zig-zag).</summary>
        public void WriteInt64Field(int fieldNumber, long value)
            => WriteVarintField(fieldNumber, unchecked((ulong)value));

        /// <summary>Writes a length-delimited field (wire type 2): bytes/string/sub-message.</summary>
        public void WriteLengthDelimitedField(int fieldNumber, ReadOnlySpan<byte> value)
        {
            WriteTag(fieldNumber, 2);
            WriteVarint((ulong)value.Length);
            for (int i = 0; i < value.Length; i++) _buffer.Add(value[i]);
        }

        /// <summary>Writes a string field (UTF-8, wire type 2).</summary>
        public void WriteStringField(int fieldNumber, string value)
            => WriteLengthDelimitedField(fieldNumber, System.Text.Encoding.UTF8.GetBytes(value));

        /// <summary>
        /// Writes a packed repeated <c>uint32</c> field (wire type 2): a single length-delimited block whose body is
        /// the concatenation of each element's varint encoding. Nebula stores <c>Ips</c>/<c>Subnets</c> this way.
        /// </summary>
        public void WritePackedUInt32Field(int fieldNumber, IReadOnlyList<uint> values)
        {
            if (values.Count == 0) return;
            var inner = new ProtobufWriter();
            foreach (uint v in values) inner.WriteVarint(v);
            WriteLengthDelimitedField(fieldNumber, inner._buffer.ToArray());
        }
    }
}
