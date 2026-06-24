namespace TqkLibrary.VpnClient.Drivers.N2n.Config
{
    /// <summary>
    /// Which payload transform the edge uses to protect the encapsulated Ethernet frame inside a PACKET. Maps to an
    /// <c>N2n.Transform.IN2nTransform</c>: <see cref="Null"/> → <c>N2nNullTransform</c> (clear), <see cref="Aes"/> →
    /// <c>N2nAesTransform</c> (AES-CBC, null IV, random 16-byte preamble). The supernode/edges in the community must use
    /// the same transform (n2n's <c>-A</c> option selects it).
    /// </summary>
    public enum N2nTransformKind
    {
        /// <summary>No encryption — the Ethernet frame is carried in the clear (n2n <c>-A1</c>). The default.</summary>
        Null,
        /// <summary>AES-CBC with a random preamble (n2n <c>-A2</c>); the AES key is supplied directly in the config.</summary>
        Aes,
    }
}
