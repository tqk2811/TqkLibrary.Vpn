namespace TqkLibrary.VpnClient.ZeroTier.Vl1.Enums
{
    /// <summary>
    /// VL1 cipher-suite selector — the low 3 bits of the flags/cipher byte (offset 18) of a VL1 packet. It tells the
    /// receiver how the packet was protected.
    /// </summary>
    public enum Vl1CipherSuite : byte
    {
        /// <summary>Poly1305 MAC only, payload not encrypted (used for HELLO, which must be readable before keys exist).</summary>
        Poly1305None = 0,

        /// <summary>Salsa20/12 encryption + Poly1305 authentication (the normal data cipher suite).</summary>
        Salsa2012Poly1305 = 1,

        /// <summary>No encryption and no authentication (debug/local only — never used on the wire by this client).</summary>
        None = 2,
    }
}
