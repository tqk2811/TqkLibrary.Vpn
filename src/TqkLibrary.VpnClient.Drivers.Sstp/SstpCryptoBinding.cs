using System.Security.Cryptography;
using System.Text;
using TqkLibrary.VpnClient.Drivers.Sstp.Enums;
using TqkLibrary.VpnClient.Drivers.Sstp.Models;

namespace TqkLibrary.VpnClient.Drivers.Sstp
{
    /// <summary>
    /// Builds the SSTP Crypto Binding attribute for a Call Connected message ([MS-SSTP] §2.2.7, §3.2.5.2):
    /// CMK = HMAC-SHA256(HLAK, seed) and Compound-MAC = HMAC-SHA256(CMK, the zeroed-MAC Call Connected packet).
    /// SHA-256 hash protocol.
    /// </summary>
    public static class SstpCryptoBinding
    {
        static readonly byte[] CmkSeed = Encoding.ASCII.GetBytes("SSTP inner method derived CMK");

        /// <summary>
        /// Builds the Crypto Binding attribute. <paramref name="nonce"/> is the 32-byte nonce from the Call
        /// Connect Ack; <paramref name="certHashSha256"/> is SHA-256 of the server's DER certificate.
        /// </summary>
        public static SstpAttribute BuildCryptoBinding(byte[] hlak, byte[] nonce, byte[] certHashSha256)
        {
            byte[] cmk = DeriveCmk(hlak);

            // value (100 bytes): Reserved(3) + HashProtocol(1) + Nonce(32) + CertHash(32) + CompoundMAC(32)
            byte[] value = new byte[100];
            value[3] = SstpConstants.CertHashProtocolSha256;
            Buffer.BlockCopy(nonce, 0, value, 4, 32);
            Buffer.BlockCopy(certHashSha256, 0, value, 36, Math.Min(32, certHashSha256.Length));
            // CompoundMAC [68..100] stays zero while computing the MAC.

            // Reconstruct the full Call Connected packet (header + body) with the MAC zeroed, then HMAC it.
            var zeroed = new SstpAttribute((byte)SstpAttributeId.CryptoBinding, value);
            byte[] body = SstpControlCodec.BuildBody(SstpMessageType.CallConnected, new[] { zeroed });
            int length = 4 + body.Length;
            byte[] packet = new byte[length];
            packet[0] = SstpConstants.Version;
            packet[1] = 0x01; // control
            packet[2] = (byte)((length >> 8) & 0x0F);
            packet[3] = (byte)(length & 0xff);
            Buffer.BlockCopy(body, 0, packet, 4, body.Length);

            byte[] cmac;
            using (var hmac = new HMACSHA256(cmk))
                cmac = hmac.ComputeHash(packet);
            Buffer.BlockCopy(cmac, 0, value, 68, 32);

            return new SstpAttribute((byte)SstpAttributeId.CryptoBinding, value);
        }

        static byte[] DeriveCmk(byte[] hlak)
        {
            // CMK = HMAC-SHA256(HLAK, "SSTP inner method derived CMK" || LEN || 0x00 || 0x01)
            // LEN = 0x20 — the CMK length in BYTES (32 for SHA-256), per [MS-SSTP] §3.2.5.2.2 and the
            // accel-ppp / Windows RRAS wire (they append len(32)=0x20, then 0x00, then the 0x01 counter).
            // The earlier 0x01 (mis-reading LEN as the high byte of "256 bits") yields a CMK no strict
            // server accepts; it stayed hidden because SoftEther/VPN Gate does not verify the Compound MAC,
            // whereas accel-ppp does and rejected it ("invalid Compound MAC"). Verified live against accel-ppp.
            byte[] data = new byte[CmkSeed.Length + 3];
            Buffer.BlockCopy(CmkSeed, 0, data, 0, CmkSeed.Length);
            data[CmkSeed.Length] = 0x20;     // CMK length = 32 bytes (SHA-256 digest length)
            data[CmkSeed.Length + 1] = 0x00;
            data[CmkSeed.Length + 2] = 0x01; // counter
            using var hmac = new HMACSHA256(hlak);
            return hmac.ComputeHash(data);
        }
    }
}
