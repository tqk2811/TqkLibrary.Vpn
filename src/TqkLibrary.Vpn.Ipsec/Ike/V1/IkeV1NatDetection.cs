using System.Globalization;
using System.Net;
using System.Security.Cryptography;

namespace TqkLibrary.Vpn.Ipsec.Ike.V1
{
    /// <summary>
    /// IKEv1 NAT-Traversal helpers (RFC 3947): the Vendor IDs that advertise NAT-T support and the NAT-D hash
    /// <c>HASH(CKY-I | CKY-R | IP | Port)</c>. Claiming source port 500 while sending from an ephemeral port makes
    /// the gateway's source NAT-D comparison fail, so it concludes there is NAT and moves to UDP/4500.
    /// </summary>
    public static class IkeV1NatDetection
    {
        /// <summary>Vendor ID for RFC 3947 NAT-T (MD5 of "RFC 3947").</summary>
        public static byte[] VendorIdRfc3947 { get; } = FromHex("4a131c81070358455c5728f20e95452f");

        /// <summary>Vendor ID for draft-ietf-ipsec-nat-t-ike-02.</summary>
        public static byte[] VendorIdDraft02 { get; } = FromHex("90cb80913ebb696e086381b5ec427b1f");

        /// <summary>Vendor ID for draft-ietf-ipsec-nat-t-ike-03.</summary>
        public static byte[] VendorIdDraft03 { get; } = FromHex("7d9419a65310ca6f2c179d9215529d56");

        /// <summary>Computes a NAT-D hash over the cookies and an IP endpoint using the negotiated Phase 1 hash.</summary>
        public static byte[] ComputeHash(HashAlgorithmName hash, byte[] cookieInitiator, byte[] cookieResponder, IPAddress ip, ushort port)
        {
            byte[] address = ip.GetAddressBytes();
            byte[] data = new byte[cookieInitiator.Length + cookieResponder.Length + address.Length + 2];
            int offset = 0;
            Buffer.BlockCopy(cookieInitiator, 0, data, offset, cookieInitiator.Length); offset += cookieInitiator.Length;
            Buffer.BlockCopy(cookieResponder, 0, data, offset, cookieResponder.Length); offset += cookieResponder.Length;
            Buffer.BlockCopy(address, 0, data, offset, address.Length); offset += address.Length;
            data[offset] = (byte)(port >> 8);
            data[offset + 1] = (byte)port;
            return IkeV1KeyMaterial.HashBytes(hash, data);
        }

        static byte[] FromHex(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = byte.Parse(hex.Substring(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            return bytes;
        }
    }
}
