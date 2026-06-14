using System.Net;
using System.Security.Cryptography;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Ipsec.Esp;
using TqkLibrary.VpnClient.Ipsec.Ike.V1;
using TqkLibrary.VpnClient.Ipsec.Ike.V1.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Ipsec.Ike.Tests
{
    public class IkeV1QuickModeTests
    {
        [Fact]
        public void NatDetection_ClaimedPortDiffersFromActual()
        {
            byte[] cookieI = Bytes(0xA0, 8), cookieR = Bytes(0xB0, 8);
            IPAddress ip = IPAddress.Parse("192.168.1.50");

            byte[] claimed500 = IkeV1NatDetection.ComputeHash(HashAlgorithmName.SHA1, cookieI, cookieR, ip, 500);
            byte[] claimed500Again = IkeV1NatDetection.ComputeHash(HashAlgorithmName.SHA1, cookieI, cookieR, ip, 500);
            byte[] ephemeral = IkeV1NatDetection.ComputeHash(HashAlgorithmName.SHA1, cookieI, cookieR, ip, 43210);

            Assert.Equal(claimed500, claimed500Again);
            Assert.NotEqual(claimed500, ephemeral); // forces the gateway to detect NAT
            Assert.Equal(20, claimed500.Length);     // SHA-1
        }

        [Fact]
        public void Phase2Keys_TwoParties_ProduceInteroperableEspSessions()
        {
            var prf = new HmacPrf(HashAlgorithmName.SHA1);
            byte[] skeyidD = Bytes(0x55, 20);
            byte[] ni = Bytes(0x11, 16), nr = Bytes(0x22, 16);
            byte[] clientSpi = { 0xC1, 0xC2, 0xC3, 0xC4 };
            byte[] serverSpi = { 0x51, 0x52, 0x53, 0x54 };
            const byte esp = IkeV1Constants.Protocol.Esp;

            IkeV1Phase2Keys clientKeys = IkeV1Phase2Keys.Derive(prf, skeyidD, esp, clientSpi, serverSpi, ni, nr, 32, 20);
            IkeV1Phase2Keys serverKeys = IkeV1Phase2Keys.Derive(prf, skeyidD, esp, serverSpi, clientSpi, ni, nr, 32, 20);

            // The SA on serverSpi is the client's outbound and the server's inbound — same keys both sides.
            Assert.Equal(clientKeys.OutboundEncryption, serverKeys.InboundEncryption);
            Assert.Equal(clientKeys.OutboundIntegrity, serverKeys.InboundIntegrity);

            EspSession client = new(ToSpi(serverSpi),
                EspCipherSuite.AesCbcHmacSha1(clientKeys.OutboundEncryption, clientKeys.OutboundIntegrity),
                ToSpi(clientSpi),
                EspCipherSuite.AesCbcHmacSha1(clientKeys.InboundEncryption, clientKeys.InboundIntegrity));
            EspSession server = new(ToSpi(clientSpi),
                EspCipherSuite.AesCbcHmacSha1(serverKeys.OutboundEncryption, serverKeys.OutboundIntegrity),
                ToSpi(serverSpi),
                EspCipherSuite.AesCbcHmacSha1(serverKeys.InboundEncryption, serverKeys.InboundIntegrity));

            byte[] packet = client.Protect(System.Text.Encoding.ASCII.GetBytes("quick mode esp"));
            Assert.True(server.TryUnprotect(packet, out byte[] recovered, out _));
            Assert.Equal("quick mode esp", System.Text.Encoding.ASCII.GetString(recovered));
        }

        [Fact]
        public void QuickModeHashes_AreDeterministic_AndNonceSensitive()
        {
            var prf = new HmacPrf(HashAlgorithmName.SHA1);
            byte[] skeyidA = Bytes(0x77, 20);
            byte[] ni = Bytes(0x11, 16), nr = Bytes(0x22, 16);
            byte[] rest = Bytes(0x30, 40);
            const uint mid = 0xCAFEBABE;

            Assert.Equal(
                IkeV1QuickMode.ComputeHash1(prf, skeyidA, mid, rest),
                IkeV1QuickMode.ComputeHash1(prf, skeyidA, mid, rest));

            byte[] h3 = IkeV1QuickMode.ComputeHash3(prf, skeyidA, mid, ni, nr);
            byte[] h3Other = IkeV1QuickMode.ComputeHash3(prf, skeyidA, mid, ni, Bytes(0x99, 16));
            Assert.NotEqual(h3, h3Other);
        }

        static uint ToSpi(byte[] spi) => (uint)((spi[0] << 24) | (spi[1] << 16) | (spi[2] << 8) | spi[3]);

        static byte[] Bytes(byte seed, int length)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = (byte)(seed + i);
            return b;
        }
    }
}
