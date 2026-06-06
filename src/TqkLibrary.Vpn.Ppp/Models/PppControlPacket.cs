namespace TqkLibrary.Vpn.Ppp.Models
{
    /// <summary>
    /// A PPP control packet (the Information field of an LCP/IPCP frame): Code, Identifier, and a payload
    /// which is either a list of options (Configure-*) or raw data (Echo/Terminate/auth).
    /// </summary>
    public sealed class PppControlPacket
    {
        /// <summary>Packet code (see <see cref="Enums.PppCode"/>).</summary>
        public byte Code { get; set; }

        /// <summary>Identifier used to match requests with replies.</summary>
        public byte Identifier { get; set; }

        /// <summary>The payload after the 4-byte Code/Id/Length header.</summary>
        public byte[] Data { get; set; } = Array.Empty<byte>();
    }
}
