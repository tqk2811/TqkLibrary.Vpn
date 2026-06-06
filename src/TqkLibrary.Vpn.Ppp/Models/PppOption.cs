namespace TqkLibrary.Vpn.Ppp.Models
{
    /// <summary>A single PPP configuration option: a type byte plus its value (RFC 1661 §6 TLV form).</summary>
    public sealed class PppOption
    {
        /// <summary>Creates an option with the given type and value.</summary>
        public PppOption(byte type, byte[] data)
        {
            Type = type;
            Data = data ?? Array.Empty<byte>();
        }

        /// <summary>Option type (LCP/IPCP option number).</summary>
        public byte Type { get; }

        /// <summary>Option value (the bytes after the 2-byte type/length header).</summary>
        public byte[] Data { get; }
    }
}
