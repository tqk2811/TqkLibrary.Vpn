using System.Text;
using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>
    /// Tests NCP cipher negotiation (V2.f): the advertised cipher catalog, the peer-info block, and that key2 sliced
    /// for a negotiated cipher (here AES-128-GCM) yields complementary keys a data channel can use.
    /// </summary>
    public class OpenVpnNcpTests
    {
        [Fact]
        public void DataCipher_ResolvesByName_AndAdvertisesList()
        {
            Assert.True(OpenVpnDataCipher.TryResolve("AES-128-GCM", out OpenVpnDataCipher c128));
            Assert.Equal(16, c128.KeySizeBytes);
            Assert.True(OpenVpnDataCipher.TryResolve("aes-256-gcm", out OpenVpnDataCipher c256)); // case-insensitive
            Assert.Equal(32, c256.KeySizeBytes);
            Assert.False(OpenVpnDataCipher.TryResolve("BF-CBC", out _)); // unsupported

            Assert.Equal("AES-256-GCM:AES-128-GCM", OpenVpnDataCipher.AdvertisedList);
        }

        [Fact]
        public void PeerInfo_CarriesCiphersAndProto()
        {
            string peerInfo = OpenVpnPeerInfo.Build();
            Assert.Contains("IV_CIPHERS=AES-256-GCM:AES-128-GCM", peerInfo);
            Assert.Contains("IV_NCP=2", peerInfo);
            Assert.Contains($"IV_PROTO={OpenVpnPeerInfo.IvProtoDataV2 | OpenVpnPeerInfo.IvProtoRequestPush}", peerInfo);
        }

        [Theory]
        [InlineData("AES-256-GCM", 32)]
        [InlineData("AES-128-GCM", 16)]
        public void NegotiatedCipher_DerivesComplementaryKeys_AndDataFlows(string cipherName, int expectedKeyLen)
        {
            Assert.True(OpenVpnDataCipher.TryResolve(cipherName, out OpenVpnDataCipher cipher));

            // Shared key2 (cipher-independent), then slice for the negotiated cipher on each side.
            var clientKs = OpenVpnKeySource2.GenerateClient();
            byte[] r1 = new byte[OpenVpnKeySource2.RandomSize], r2 = new byte[OpenVpnKeySource2.RandomSize];
            for (int i = 0; i < r1.Length; i++) { r1[i] = (byte)(i + 5); r2[i] = (byte)(i + 50); }
            var serverKs = new OpenVpnKeySource2(Array.Empty<byte>(), r1, r2);

            byte[] key2 = OpenVpnKeyMethod2.DeriveKey2(clientKs, serverKs, 0xAAAA, 0xBBBB);
            var clientKeys = new OpenVpnKeyMaterial(key2).DeriveDataKeys(cipher, isServer: false);
            var serverKeys = OpenVpnKeyMethod2.SliceDataKeys(key2, cipher, isServer: true);

            Assert.Equal(expectedKeyLen, clientKeys.SendCipherKey.Length);
            Assert.Equal(clientKeys.SendCipherKey, serverKeys.ReceiveCipherKey);
            Assert.Equal(clientKeys.ReceiveCipherKey, serverKeys.SendCipherKey);

            // The data channel auto-sizes its AES-GCM to the key length; a packet round-trips.
            var clientDc = new OpenVpnDataChannel(clientKeys);
            var serverDc = new OpenVpnDataChannel(serverKeys);
            byte[] payload = Encoding.ASCII.GetBytes($"data over {cipherName}");
            Assert.True(serverDc.TryUnprotect(clientDc.Protect(payload), out byte[] got));
            Assert.Equal(payload, got);
        }
    }
}
