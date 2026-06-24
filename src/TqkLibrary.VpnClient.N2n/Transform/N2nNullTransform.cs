using TqkLibrary.VpnClient.N2n.Transform.Interfaces;

namespace TqkLibrary.VpnClient.N2n.Transform
{
    /// <summary>
    /// The n2n v3 NULL transform (<see cref="Wire.Enums.N2nTransformId.Null"/> = 1): the Ethernet frame is carried in
    /// the clear, so encode/decode are the identity. Used when the community runs without payload encryption (and for
    /// the first live-interop run, where only registration is being validated).
    /// </summary>
    public sealed class N2nNullTransform : IN2nTransform
    {
        /// <inheritdoc/>
        public Wire.Enums.N2nTransformId Id => Wire.Enums.N2nTransformId.Null;

        /// <inheritdoc/>
        public byte[] Encode(ReadOnlySpan<byte> plaintext) => plaintext.ToArray();

        /// <inheritdoc/>
        public byte[] Decode(ReadOnlySpan<byte> ciphertext) => ciphertext.ToArray();
    }
}
