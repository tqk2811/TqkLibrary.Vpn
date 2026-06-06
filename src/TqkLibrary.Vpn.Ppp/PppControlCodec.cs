using TqkLibrary.Vpn.Ppp.Models;

namespace TqkLibrary.Vpn.Ppp
{
    /// <summary>
    /// Encodes/decodes PPP control packets (Code, Identifier, Length, payload) and their TLV options,
    /// shared by LCP and IPCP (RFC 1661 §5–6).
    /// </summary>
    public static class PppControlCodec
    {
        /// <summary>Parses the Information field of an LCP/IPCP frame.</summary>
        public static PppControlPacket Parse(ReadOnlySpan<byte> packet)
        {
            if (packet.Length < 4) throw new ArgumentException("PPP control packet too short.", nameof(packet));
            int length = (packet[2] << 8) | packet[3];
            if (length < 4 || length > packet.Length) throw new ArgumentException("PPP control packet length out of range.", nameof(packet));
            return new PppControlPacket
            {
                Code = packet[0],
                Identifier = packet[1],
                Data = packet.Slice(4, length - 4).ToArray(),
            };
        }

        /// <summary>Builds a control packet with the given code, identifier and payload.</summary>
        public static byte[] Build(byte code, byte identifier, ReadOnlySpan<byte> data)
        {
            int length = 4 + data.Length;
            byte[] result = new byte[length];
            result[0] = code;
            result[1] = identifier;
            result[2] = (byte)(length >> 8);
            result[3] = (byte)(length & 0xff);
            data.CopyTo(result.AsSpan(4));
            return result;
        }

        /// <summary>Builds a Configure-* packet whose payload is the encoded <paramref name="options"/>.</summary>
        public static byte[] BuildConfigure(byte code, byte identifier, IEnumerable<PppOption> options)
            => Build(code, identifier, EncodeOptions(options));

        /// <summary>Encodes a sequence of options into TLV bytes.</summary>
        public static byte[] EncodeOptions(IEnumerable<PppOption> options)
        {
            var output = new List<byte>();
            foreach (PppOption option in options)
            {
                int len = 2 + option.Data.Length;
                if (len > 255) throw new ArgumentException("PPP option too long.");
                output.Add(option.Type);
                output.Add((byte)len);
                output.AddRange(option.Data);
            }
            return output.ToArray();
        }

        /// <summary>Parses TLV option bytes (e.g. the payload of a Configure-Request).</summary>
        public static List<PppOption> ParseOptions(ReadOnlySpan<byte> data)
        {
            var options = new List<PppOption>();
            int i = 0;
            while (i + 2 <= data.Length)
            {
                byte type = data[i];
                byte len = data[i + 1];
                if (len < 2 || i + len > data.Length) break; // malformed -> stop
                options.Add(new PppOption(type, data.Slice(i + 2, len - 2).ToArray()));
                i += len;
            }
            return options;
        }
    }
}
