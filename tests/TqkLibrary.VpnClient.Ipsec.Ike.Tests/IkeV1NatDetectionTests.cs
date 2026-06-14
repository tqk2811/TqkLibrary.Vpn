using System.Net;
using System.Security.Cryptography;
using TqkLibrary.VpnClient.Ipsec.Ike.V1;
using Xunit;

namespace TqkLibrary.VpnClient.Ipsec.Ike.Tests
{
    /// <summary>
    /// Pins the RFC 3947 NAT-D primitives the honest-first handshake relies on: the hash is deterministic and
    /// address/port-sensitive, and the membership compare distinguishes a present from an absent endpoint hash.
    /// The end-to-end NAT verdict through a real <see cref="IkeV1Client"/> is covered in <c>IkeV1HandshakeTests</c>.
    /// </summary>
    public class IkeV1NatDetectionTests
    {
        static readonly byte[] CookieI = Bytes(0x01, 8);
        static readonly byte[] CookieR = Bytes(0x20, 8);

        [Fact]
        public void ComputeHash_IsDeterministic_AndSensitiveToPort()
        {
            IPAddress ip = IPAddress.Parse("203.0.113.7");
            byte[] a = IkeV1NatDetection.ComputeHash(HashAlgorithmName.SHA1, CookieI, CookieR, ip, 500);
            byte[] b = IkeV1NatDetection.ComputeHash(HashAlgorithmName.SHA1, CookieI, CookieR, ip, 500);
            byte[] differentPort = IkeV1NatDetection.ComputeHash(HashAlgorithmName.SHA1, CookieI, CookieR, ip, 4500);

            Assert.Equal(a, b);             // same inputs → same hash
            Assert.NotEqual(a, differentPort); // port is part of the hash
            Assert.Equal(20, a.Length);     // SHA-1 digest
        }

        [Fact]
        public void ComputeHash_IsSensitiveToAddress()
        {
            byte[] one = IkeV1NatDetection.ComputeHash(HashAlgorithmName.SHA1, CookieI, CookieR, IPAddress.Parse("198.51.100.1"), 500);
            byte[] two = IkeV1NatDetection.ComputeHash(HashAlgorithmName.SHA1, CookieI, CookieR, IPAddress.Parse("198.51.100.2"), 500);
            Assert.NotEqual(one, two);
        }

        [Fact]
        public void MatchesAny_TrueWhenPresent_FalseWhenAbsent()
        {
            byte[] h1 = IkeV1NatDetection.ComputeHash(HashAlgorithmName.SHA1, CookieI, CookieR, IPAddress.Parse("198.51.100.1"), 500);
            byte[] h2 = IkeV1NatDetection.ComputeHash(HashAlgorithmName.SHA1, CookieI, CookieR, IPAddress.Parse("198.51.100.2"), 4500);
            byte[][] received = { h1, h2 };

            Assert.True(IkeV1NatDetection.MatchesAny(received, h1));
            Assert.True(IkeV1NatDetection.MatchesAny(received, h2));

            byte[] absent = IkeV1NatDetection.ComputeHash(HashAlgorithmName.SHA1, CookieI, CookieR, IPAddress.Parse("10.0.0.9"), 500);
            Assert.False(IkeV1NatDetection.MatchesAny(received, absent));
        }

        static byte[] Bytes(byte seed, int length)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = (byte)(seed + i);
            return b;
        }
    }
}
