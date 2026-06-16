using System.Text;
using TqkLibrary.VpnClient.Crypto.Abstractions.Interfaces;

namespace TqkLibrary.VpnClient.Ipsec.Ike.V2
{
    /// <summary>
    /// Pre-shared-key AUTH computation (RFC 7296 §2.15):
    /// <c>AUTH = prf(prf(PSK, "Key Pad for IKEv2"), SignedOctets)</c>, where the initiator's
    /// <c>SignedOctets = RealMessage1 | Nr | prf(SK_pi, RestOfIDi)</c> and the responder's
    /// uses <c>RealMessage2 | Ni | prf(SK_pr, RestOfIDr)</c>.
    /// </summary>
    public static class IkePskAuth
    {
        static readonly byte[] KeyPad = Encoding.ASCII.GetBytes("Key Pad for IKEv2");

        /// <summary>Computes the initiator's AUTH MIC.</summary>
        public static byte[] ComputeInitiatorAuth(
            IPrf prf, byte[] preSharedKey, byte[] realMessage1, byte[] nonceResponder, byte[] skPi, byte[] restOfIdInitiator)
            => ComputeAuth(prf, preSharedKey, realMessage1, nonceResponder, skPi, restOfIdInitiator);

        /// <summary>Computes the responder's AUTH MIC (what we expect to receive and verify).</summary>
        public static byte[] ComputeResponderAuth(
            IPrf prf, byte[] preSharedKey, byte[] realMessage2, byte[] nonceInitiator, byte[] skPr, byte[] restOfIdResponder)
            => ComputeAuth(prf, preSharedKey, realMessage2, nonceInitiator, skPr, restOfIdResponder);

        static byte[] ComputeAuth(IPrf prf, byte[] preSharedKey, byte[] realMessage, byte[] peerNonce, byte[] skP, byte[] restOfId)
        {
            byte[] innerKey = Prf(prf, preSharedKey, KeyPad);
            byte[] macedId = Prf(prf, skP, restOfId);

            byte[] signed = new byte[realMessage.Length + peerNonce.Length + macedId.Length];
            int offset = 0;
            Buffer.BlockCopy(realMessage, 0, signed, offset, realMessage.Length); offset += realMessage.Length;
            Buffer.BlockCopy(peerNonce, 0, signed, offset, peerNonce.Length); offset += peerNonce.Length;
            Buffer.BlockCopy(macedId, 0, signed, offset, macedId.Length);

            return Prf(prf, innerKey, signed);
        }

        static byte[] Prf(IPrf prf, byte[] key, byte[] data)
        {
            byte[] output = new byte[prf.OutputSizeInBytes];
            prf.Compute(key, data, output);
            return output;
        }
    }
}
