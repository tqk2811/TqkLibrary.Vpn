using System.Security.Cryptography;
using System.Text;
using TqkLibrary.Vpn.Crypto;

namespace TqkLibrary.Vpn.Ppp.Auth
{
    /// <summary>
    /// MS-CHAPv2 client-side crypto (RFC 2759): NT password hash (MD4), challenge hash (SHA-1),
    /// and the 24-byte NT-Response via three DES operations. MS-CHAPv2 is weak — used because L2TP/SSTP mandate it.
    /// </summary>
    public static class MsChapV2
    {
        /// <summary>NtPasswordHash = MD4(UTF-16LE(password)) — 16 bytes (RFC 2759 §8.3).</summary>
        public static byte[] NtPasswordHash(string password)
            => Md4.Hash(Encoding.Unicode.GetBytes(password));

        /// <summary>ChallengeHash = first 8 bytes of SHA1(PeerChallenge || AuthenticatorChallenge || UserName) (RFC 2759 §8.2).</summary>
        public static byte[] ChallengeHash(byte[] peerChallenge, byte[] authenticatorChallenge, string userName)
        {
            byte[] user = Encoding.ASCII.GetBytes(userName);
            byte[] input = new byte[peerChallenge.Length + authenticatorChallenge.Length + user.Length];
            Buffer.BlockCopy(peerChallenge, 0, input, 0, peerChallenge.Length);
            Buffer.BlockCopy(authenticatorChallenge, 0, input, peerChallenge.Length, authenticatorChallenge.Length);
            Buffer.BlockCopy(user, 0, input, peerChallenge.Length + authenticatorChallenge.Length, user.Length);

            using var sha1 = SHA1.Create();
            byte[] hash = sha1.ComputeHash(input);
            byte[] challenge = new byte[8];
            Buffer.BlockCopy(hash, 0, challenge, 0, 8);
            return challenge;
        }

        /// <summary>ChallengeResponse: DES-encrypt the 8-byte challenge under three keys from the padded password hash (RFC 2759 §8.5).</summary>
        public static byte[] ChallengeResponse(byte[] challenge8, byte[] passwordHash16)
        {
            byte[] zHash = new byte[21]; // NT hash padded with 5 zero bytes
            Buffer.BlockCopy(passwordHash16, 0, zHash, 0, 16);

            byte[] response = new byte[24];
            for (int i = 0; i < 3; i++)
            {
                byte[] key = ExpandDesKey(zHash, i * 7);
                byte[] block = Des.EncryptBlock(key, challenge8);
                Buffer.BlockCopy(block, 0, response, i * 8, 8);
            }
            return response;
        }

        /// <summary>GenerateNTResponse: the full 24-byte NT-Response (RFC 2759 §8.1).</summary>
        public static byte[] GenerateNTResponse(byte[] authenticatorChallenge, byte[] peerChallenge, string userName, string password)
        {
            byte[] challenge = ChallengeHash(peerChallenge, authenticatorChallenge, userName);
            byte[] passwordHash = NtPasswordHash(password);
            return ChallengeResponse(challenge, passwordHash);
        }

        /// <summary>Expands 7 key bytes (from <paramref name="source"/> at <paramref name="offset"/>) into an 8-byte DES key (parity bit = 0).</summary>
        static byte[] ExpandDesKey(byte[] source, int offset)
        {
            byte[] s = new byte[7];
            Buffer.BlockCopy(source, offset, s, 0, 7);
            byte[] key = new byte[8];
            key[0] = (byte)(s[0] >> 1);
            key[1] = (byte)(((s[0] & 0x01) << 6) | (s[1] >> 2));
            key[2] = (byte)(((s[1] & 0x03) << 5) | (s[2] >> 3));
            key[3] = (byte)(((s[2] & 0x07) << 4) | (s[3] >> 4));
            key[4] = (byte)(((s[3] & 0x0F) << 3) | (s[4] >> 5));
            key[5] = (byte)(((s[4] & 0x1F) << 2) | (s[5] >> 6));
            key[6] = (byte)(((s[5] & 0x3F) << 1) | (s[6] >> 7));
            key[7] = (byte)(s[6] & 0x7F);
            for (int i = 0; i < 8; i++) key[i] = (byte)(key[i] << 1); // 7 data bits high, parity bit low
            return key;
        }
    }
}
