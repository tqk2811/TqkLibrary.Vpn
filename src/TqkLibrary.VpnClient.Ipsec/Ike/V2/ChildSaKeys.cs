using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V2
{
    /// <summary>
    /// CHILD_SA keying material derived during IKE_AUTH (RFC 7296 §2.17, no PFS):
    /// <c>KEYMAT = prf+(SK_d, Ni | Nr)</c>, split as
    /// <c>{encr_i | integ_i | encr_r | integ_r}</c> — the initiator-to-responder keys come first.
    /// </summary>
    public sealed class ChildSaKeys
    {
        ChildSaKeys(byte[] encrInitiator, byte[] integInitiator, byte[] encrResponder, byte[] integResponder)
        {
            EncryptionInitiator = encrInitiator;
            IntegrityInitiator = integInitiator;
            EncryptionResponder = encrResponder;
            IntegrityResponder = integResponder;
        }

        /// <summary>Encryption key for the initiator→responder direction.</summary>
        public byte[] EncryptionInitiator { get; }

        /// <summary>Integrity key for the initiator→responder direction.</summary>
        public byte[] IntegrityInitiator { get; }

        /// <summary>Encryption key for the responder→initiator direction.</summary>
        public byte[] EncryptionResponder { get; }

        /// <summary>Integrity key for the responder→initiator direction.</summary>
        public byte[] IntegrityResponder { get; }

        /// <summary>Derives the four ESP keys for an AES-CBC-256 + HMAC-SHA-256-128 CHILD_SA.</summary>
        public static ChildSaKeys DeriveDefault(byte[] skD, byte[] nonceInitiator, byte[] nonceResponder)
            => Derive(HmacPrf.Sha256(), skD, nonceInitiator, nonceResponder, encryptionKeyLength: 32, integrityKeyLength: 32);

        /// <summary>Derives the four keys with the given per-direction encryption/integrity key lengths.</summary>
        public static ChildSaKeys Derive(
            IPrf prf, byte[] skD, byte[] nonceInitiator, byte[] nonceResponder, int encryptionKeyLength, int integrityKeyLength)
        {
            byte[] seed = new byte[nonceInitiator.Length + nonceResponder.Length];
            Buffer.BlockCopy(nonceInitiator, 0, seed, 0, nonceInitiator.Length);
            Buffer.BlockCopy(nonceResponder, 0, seed, nonceInitiator.Length, nonceResponder.Length);

            int total = 2 * (encryptionKeyLength + integrityKeyLength);
            byte[] keymat = PrfPlus.Expand(prf, skD, seed, total);

            int o = 0;
            byte[] encrI = Slice(keymat, ref o, encryptionKeyLength);
            byte[] integI = Slice(keymat, ref o, integrityKeyLength);
            byte[] encrR = Slice(keymat, ref o, encryptionKeyLength);
            byte[] integR = Slice(keymat, ref o, integrityKeyLength);
            return new ChildSaKeys(encrI, integI, encrR, integR);
        }

        static byte[] Slice(byte[] source, ref int offset, int length)
        {
            byte[] result = new byte[length];
            Buffer.BlockCopy(source, offset, result, 0, length);
            offset += length;
            return result;
        }
    }
}
