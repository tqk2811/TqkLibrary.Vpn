namespace TqkLibrary.VpnClient.N2n.Wire.Enums
{
    /// <summary>
    /// n2n v3 payload transform identifier (<c>n2n_transform_t</c>), stored in the PACKET body's <c>transform</c> byte and
    /// negotiated against the supernode/edge. Selects which cipher protects the encapsulated Ethernet frame.
    /// </summary>
    public enum N2nTransformId : byte
    {
        /// <summary>Invalid / unset.</summary>
        Invalid = 0,
        /// <summary>No encryption — the Ethernet frame is carried in the clear.</summary>
        Null = 1,
        /// <summary>Twofish-CTS (legacy v1/v2). Not implemented here.</summary>
        Twofish = 2,
        /// <summary>AES-CBC with a random 16-byte preamble acting as the IV (this project's encrypting transform).</summary>
        Aes = 3,
        /// <summary>ChaCha20 stream cipher. Not implemented here.</summary>
        ChaCha20 = 4,
        /// <summary>Speck-CTR. Not implemented here (avoided — Speck is not in Crypto).</summary>
        Speck = 5,
    }
}
