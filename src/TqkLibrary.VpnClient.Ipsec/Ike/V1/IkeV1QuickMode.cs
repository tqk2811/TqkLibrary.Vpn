using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V1
{
    /// <summary>
    /// Quick Mode authentication hashes (RFC 2409 §5.5), keyed by SKEYID_a:
    /// HASH(1) over <c>M-ID | rest-of-QM1</c>, HASH(2) over <c>M-ID | Ni_b | rest-of-QM2</c>, and
    /// HASH(3) over <c>0 | M-ID | Ni_b | Nr_b</c>. "Rest" is the payloads after the HASH payload, on the wire.
    /// </summary>
    public static class IkeV1QuickMode
    {
        /// <summary>HASH(1): the initiator's QM1 authentication over the message body following the HASH payload.</summary>
        public static byte[] ComputeHash1(IPrf prf, byte[] skeyidA, uint messageId, byte[] messageAfterHash)
            => Prf(prf, skeyidA, IkeV1KeyMaterial.Concat(MessageId(messageId), messageAfterHash));

        /// <summary>HASH(2): the responder's QM2 authentication, which folds in the initiator's nonce value.</summary>
        public static byte[] ComputeHash2(IPrf prf, byte[] skeyidA, uint messageId, byte[] nonceInitiator, byte[] messageAfterHash)
            => Prf(prf, skeyidA, IkeV1KeyMaterial.Concat(MessageId(messageId), nonceInitiator, messageAfterHash));

        /// <summary>HASH(3): the initiator's QM3 proof of liveness over both nonces.</summary>
        public static byte[] ComputeHash3(IPrf prf, byte[] skeyidA, uint messageId, byte[] nonceInitiator, byte[] nonceResponder)
            => Prf(prf, skeyidA, IkeV1KeyMaterial.Concat(new byte[] { 0 }, MessageId(messageId), nonceInitiator, nonceResponder));

        static byte[] MessageId(uint messageId)
            => new[] { (byte)(messageId >> 24), (byte)(messageId >> 16), (byte)(messageId >> 8), (byte)messageId };

        static byte[] Prf(IPrf prf, byte[] key, byte[] data)
        {
            byte[] output = new byte[prf.OutputSizeInBytes];
            prf.Compute(key, data, output);
            return output;
        }
    }
}
