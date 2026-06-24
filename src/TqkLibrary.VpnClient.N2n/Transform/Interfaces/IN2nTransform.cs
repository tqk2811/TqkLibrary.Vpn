namespace TqkLibrary.VpnClient.N2n.Transform.Interfaces
{
    /// <summary>
    /// A reversible n2n v3 PACKET payload transform: it converts an inner Ethernet frame to the on-wire payload bytes
    /// and back. The <see cref="Id"/> is the value written to the PACKET body's <c>transform</c> byte so the receiver
    /// knows which transform to apply.
    /// </summary>
    public interface IN2nTransform
    {
        /// <summary>The transform id stamped into the PACKET body.</summary>
        Wire.Enums.N2nTransformId Id { get; }

        /// <summary>Converts a plaintext Ethernet frame to the on-wire payload bytes.</summary>
        byte[] Encode(ReadOnlySpan<byte> plaintext);

        /// <summary>Recovers the Ethernet frame from on-wire payload bytes.</summary>
        byte[] Decode(ReadOnlySpan<byte> ciphertext);
    }
}
