using System.Text;

namespace TqkLibrary.VpnClient.OpenVpn.DataChannel
{
    /// <summary>
    /// OpenVPN text control messages over the established TLS channel (<c>PUSH_REQUEST</c>, <c>PUSH_REPLY,…</c>,
    /// <c>AUTH_FAILED</c>, <c>RESTART</c>, …). Unlike the key-method-2 message these are plain NUL-terminated ASCII with
    /// no 4-byte sentinel — they flow only after key negotiation, so the reader is purely sequential.
    /// </summary>
    public static class OpenVpnControlMessage
    {
        /// <summary>Encodes a control string as it rides the TLS stream: the ASCII bytes followed by a NUL.</summary>
        public static byte[] Build(string text)
        {
            if (text is null) throw new ArgumentNullException(nameof(text));
            byte[] ascii = Encoding.ASCII.GetBytes(text);
            byte[] message = new byte[ascii.Length + 1];
            Array.Copy(ascii, message, ascii.Length);
            return message; // trailing NUL already zero
        }

        /// <summary>Reads one NUL-terminated control string from <paramref name="stream"/> (the TLS pipe).</summary>
        public static async Task<string> ReadAsync(Stream stream, CancellationToken cancellationToken = default)
        {
            if (stream is null) throw new ArgumentNullException(nameof(stream));
            var bytes = new List<byte>(64);
            byte[] one = new byte[1];
            while (true)
            {
                int n = await stream.ReadAsync(one, 0, 1, cancellationToken).ConfigureAwait(false);
                if (n == 0) throw new EndOfStreamException("OpenVPN control channel closed while reading a control message.");
                if (one[0] == 0) break; // NUL terminates the string
                bytes.Add(one[0]);
            }
            return Encoding.ASCII.GetString(bytes.ToArray());
        }
    }
}
