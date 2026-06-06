using TqkLibrary.Vpn.Crypto;
using Xunit;

namespace TqkLibrary.Vpn.Crypto.Tests
{
    public class DesTests
    {
        // Classic FIPS 46-3 / Schneier worked example.
        [Fact]
        public void Des_EncryptBlock_MatchesKnownVector()
        {
            byte[] key = Convert.FromHexString("133457799BBCDFF1");
            byte[] plaintext = Convert.FromHexString("0123456789ABCDEF");
            byte[] expected = Convert.FromHexString("85E813540F0AB405");

            byte[] cipher = Des.EncryptBlock(key, plaintext);
            Assert.Equal(expected, cipher);
        }
    }
}
