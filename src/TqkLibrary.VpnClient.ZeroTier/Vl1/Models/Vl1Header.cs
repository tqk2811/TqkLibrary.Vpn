using TqkLibrary.VpnClient.ZeroTier.Identity.Models;
using TqkLibrary.VpnClient.ZeroTier.Vl1.Enums;

namespace TqkLibrary.VpnClient.ZeroTier.Vl1.Models
{
    /// <summary>
    /// The fixed 28-byte VL1 packet header (big-endian). Layout:
    /// <list type="bullet">
    ///   <item><description>[0..8)  packet ID — a random 64-bit value that doubles as the Salsa20 nonce/IV base.</description></item>
    ///   <item><description>[8..13) destination address (40-bit).</description></item>
    ///   <item><description>[13..18) source address (40-bit).</description></item>
    ///   <item><description>[18] flags + cipher — high 5 bits flags, low 3 bits <see cref="Vl1CipherSuite"/>.</description></item>
    ///   <item><description>[19..27) MAC — 8-byte truncated Poly1305 tag over the encrypted section.</description></item>
    ///   <item><description>[27] verb byte — high 3 bits flags (hops/fragment), low 5 bits <see cref="Vl1Verb"/>.</description></item>
    /// </list>
    /// The verb byte is the first byte of the encrypted section: it and the rest of the payload are what Salsa20/12
    /// covers and Poly1305 authenticates. Bytes [0..19) (everything up to and including the cipher byte) travel in the
    /// clear; the MAC field [19..27) is filled after the tag is computed.
    /// </summary>
    public sealed class Vl1Header
    {
        /// <summary>
        /// Length of the header including the verb byte (28). The clear portion is bytes [0..27); the verb byte at
        /// offset 27 is the first byte of the encrypted section, so a full packet is
        /// <see cref="EncryptedSectionOffset"/> + (verb + payload), not <see cref="Size"/> + payload.
        /// </summary>
        public const int Size = 28;

        /// <summary>Offset of the first encrypted/authenticated byte (the verb byte); also the clear-header length.</summary>
        public const int EncryptedSectionOffset = 27;

        /// <summary>Offset of the 8-byte MAC field.</summary>
        public const int MacOffset = 19;

        /// <summary>Length of the truncated Poly1305 MAC carried on the wire.</summary>
        public const int MacSize = 8;

        /// <summary>The random 64-bit packet ID (also the Salsa20 nonce base).</summary>
        public ulong PacketId { get; set; }

        /// <summary>Destination node address (40-bit).</summary>
        public ZeroTierAddress Destination { get; set; }

        /// <summary>Source node address (40-bit).</summary>
        public ZeroTierAddress Source { get; set; }

        /// <summary>Flags carried in the high 5 bits of byte 18 (hop count etc.); usually 0 on send.</summary>
        public byte Flags { get; set; }

        /// <summary>Cipher suite (low 3 bits of byte 18).</summary>
        public Vl1CipherSuite Cipher { get; set; }

        /// <summary>Verb-byte flags (high 3 bits of byte 27 — fragment/hops); usually 0 on send.</summary>
        public byte VerbFlags { get; set; }

        /// <summary>The packet verb (low 5 bits of byte 27).</summary>
        public Vl1Verb Verb { get; set; }
    }
}
