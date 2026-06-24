using System.Text;
using TqkLibrary.VpnClient.Tinc.Meta.Enums;

namespace TqkLibrary.VpnClient.Tinc.Meta
{
    /// <summary>
    /// One tinc meta-connection request line: a leading integer request code followed by space-separated fields,
    /// terminated by <c>'\n'</c> on the wire (e.g. <c>"0 client 17.7"</c> for an ID, <c>"12 a b ..."</c> for ADD_EDGE).
    /// Before SPTPS is keyed these lines are sent in the clear; afterwards they are the plaintext payload of an
    /// application SPTPS record. This type only codecs the line text — it does not interpret request semantics.
    /// </summary>
    public sealed class TincMetaRequest
    {
        /// <summary>The request code (first field of the line).</summary>
        public TincRequestType Type { get; }

        /// <summary>The raw request code integer (preserves unknown codes outside <see cref="TincRequestType"/>).</summary>
        public int RawType { get; }

        /// <summary>The fields after the request code (split on single spaces).</summary>
        public IReadOnlyList<string> Arguments { get; }

        public TincMetaRequest(TincRequestType type, params string[] arguments)
            : this((int)type, arguments) { }

        public TincMetaRequest(int rawType, params string[] arguments)
        {
            RawType = rawType;
            Type = (TincRequestType)rawType;
            Arguments = arguments ?? Array.Empty<string>();
        }

        /// <summary>Builds the ID request <c>"0 &lt;name&gt; &lt;major&gt;.&lt;minor&gt;"</c>.</summary>
        public static TincMetaRequest Id(string name, int protocolMajor, int protocolMinor)
            => new TincMetaRequest(TincRequestType.Id, name, $"{protocolMajor}.{protocolMinor}");

        /// <summary>Serialises this request to its wire line including the trailing <c>'\n'</c>.</summary>
        public byte[] ToBytes()
        {
            var sb = new StringBuilder();
            sb.Append(RawType.ToString(System.Globalization.CultureInfo.InvariantCulture));
            foreach (string arg in Arguments)
            {
                sb.Append(' ');
                sb.Append(arg);
            }
            sb.Append('\n');
            return Encoding.ASCII.GetBytes(sb.ToString());
        }

        /// <summary>Parses one line (with or without a trailing newline) into a request.</summary>
        public static TincMetaRequest Parse(string line)
        {
            string trimmed = line.TrimEnd('\r', '\n');
            string[] parts = trimmed.Split(' ');
            if (parts.Length == 0 || !int.TryParse(parts[0], out int code))
                throw new FormatException($"Malformed tinc request line: '{line}'.");
            string[] args;
            if (parts.Length > 1)
            {
                args = new string[parts.Length - 1];
                Array.Copy(parts, 1, args, 0, args.Length);
            }
            else
            {
                args = Array.Empty<string>();
            }
            return new TincMetaRequest(code, args);
        }
    }
}
