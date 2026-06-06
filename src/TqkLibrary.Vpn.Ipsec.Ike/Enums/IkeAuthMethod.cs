namespace TqkLibrary.Vpn.Ipsec.Ike.Enums
{
    /// <summary>Authentication methods in the AUTH payload (RFC 7296 §3.8).</summary>
    public enum IkeAuthMethod : byte
    {
        /// <summary>RSA digital signature.</summary>
        RsaSignature = 1,

        /// <summary>Shared Key Message Integrity Code (pre-shared key).</summary>
        SharedKey = 2,

        /// <summary>DSS digital signature.</summary>
        DssSignature = 3,
    }
}
