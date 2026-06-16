using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V1
{
    /// <summary>
    /// IKEv1 Quick Mode (Phase 2) keying material (RFC 2409 §5.5, no PFS):
    /// <c>KEYMAT = prf+(SKEYID_d, protocol | SPI | Ni_b | Nr_b)</c>, computed per SA (per SPI) and split into the
    /// ESP encryption key followed by the integrity key. The SA addressed by our SPI is inbound; the peer's is outbound.
    /// </summary>
    public sealed class IkeV1Phase2Keys
    {
        IkeV1Phase2Keys(byte[] inEnc, byte[] inInteg, byte[] outEnc, byte[] outInteg)
        {
            InboundEncryption = inEnc; InboundIntegrity = inInteg; OutboundEncryption = outEnc; OutboundIntegrity = outInteg;
        }

        /// <summary>Encryption key for packets arriving on our SPI (we decrypt).</summary>
        public byte[] InboundEncryption { get; }

        /// <summary>Integrity key for packets arriving on our SPI.</summary>
        public byte[] InboundIntegrity { get; }

        /// <summary>Encryption key for packets we send on the peer's SPI.</summary>
        public byte[] OutboundEncryption { get; }

        /// <summary>Integrity key for packets we send on the peer's SPI.</summary>
        public byte[] OutboundIntegrity { get; }

        /// <summary>Derives both directions' ESP keys for AES-CBC + HMAC (no PFS).</summary>
        public static IkeV1Phase2Keys Derive(
            IPrf prf, byte[] skeyidD, byte protocol, byte[] inboundSpi, byte[] outboundSpi,
            byte[] nonceInitiator, byte[] nonceResponder, int encryptionKeyLength, int integrityKeyLength)
        {
            byte[] inbound = Keymat(prf, skeyidD, protocol, inboundSpi, nonceInitiator, nonceResponder, encryptionKeyLength + integrityKeyLength);
            byte[] outbound = Keymat(prf, skeyidD, protocol, outboundSpi, nonceInitiator, nonceResponder, encryptionKeyLength + integrityKeyLength);

            return new IkeV1Phase2Keys(
                Slice(inbound, 0, encryptionKeyLength), Slice(inbound, encryptionKeyLength, integrityKeyLength),
                Slice(outbound, 0, encryptionKeyLength), Slice(outbound, encryptionKeyLength, integrityKeyLength));
        }

        static byte[] Keymat(IPrf prf, byte[] skeyidD, byte protocol, byte[] spi, byte[] ni, byte[] nr, int length)
        {
            byte[] seed = IkeV1KeyMaterial.Concat(new[] { protocol }, spi, ni, nr);
            var blocks = new List<byte>();
            byte[] previous = Prf(prf, skeyidD, seed); // K1 = prf(SKEYID_d, protocol|SPI|Ni|Nr)
            blocks.AddRange(previous);
            while (blocks.Count < length)
            {
                previous = Prf(prf, skeyidD, IkeV1KeyMaterial.Concat(previous, seed)); // Kn = prf(SKEYID_d, K(n-1)|seed)
                blocks.AddRange(previous);
            }
            return blocks.GetRange(0, length).ToArray();
        }

        static byte[] Prf(IPrf prf, byte[] key, byte[] data)
        {
            byte[] output = new byte[prf.OutputSizeInBytes];
            prf.Compute(key, data, output);
            return output;
        }

        static byte[] Slice(byte[] source, int offset, int length)
        {
            byte[] result = new byte[length];
            Buffer.BlockCopy(source, offset, result, 0, length);
            return result;
        }
    }
}
