using TqkLibrary.VpnClient.Tinc.Hosts;
using TqkLibrary.VpnClient.Tinc.Meta;
using TqkLibrary.VpnClient.Tinc.Meta.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.Tinc.Tests
{
    public class MetaAndHostTests
    {
        [Fact]
        public void IdRequest_FormatsAsExpected()
        {
            var id = TincMetaRequest.Id("client", 17, 7);
            byte[] wire = id.ToBytes();
            Assert.Equal("0 client 17.7\n", System.Text.Encoding.ASCII.GetString(wire));
        }

        [Fact]
        public void Request_RoundTrips()
        {
            var req = new TincMetaRequest(TincRequestType.AddEdge, "a", "b", "1.2.3.4", "655", "0", "10");
            byte[] wire = req.ToBytes();
            var parsed = TincMetaRequest.Parse(System.Text.Encoding.ASCII.GetString(wire));
            Assert.Equal(TincRequestType.AddEdge, parsed.Type);
            Assert.Equal(new[] { "a", "b", "1.2.3.4", "655", "0", "10" }, parsed.Arguments);
        }

        [Fact]
        public void Parse_UnknownCode_PreservedAsRaw()
        {
            var parsed = TincMetaRequest.Parse("99 foo bar");
            Assert.Equal(99, parsed.RawType);
            Assert.Equal(new[] { "foo", "bar" }, parsed.Arguments);
        }

        [Fact]
        public void HostConfig_ParsesEd25519AndFields()
        {
            // 32-byte key (all 0x01) → base64 unpadded.
            byte[] key = new byte[32];
            for (int i = 0; i < 32; i++) key[i] = 1;
            string b64 = TincHostConfig.EncodeBase64Key(key);
            Assert.Equal(43, b64.Length);

            string text =
                "Name = server\n" +
                "-----BEGIN RSA PUBLIC KEY-----\n" +
                "MIIB...junk...\n" +
                "-----END RSA PUBLIC KEY-----\n" +
                $"Ed25519PublicKey = {b64}\n" +
                "Address = 10.9.0.1\n" +
                "Port = 655\n" +
                "Subnet = 10.9.0.0/24\n";

            var cfg = TincHostConfig.Parse(text);
            Assert.Equal("server", cfg.Name);
            Assert.NotNull(cfg.Ed25519PublicKey);
            Assert.Equal(key, cfg.Ed25519PublicKey);
            Assert.Equal(new[] { "10.9.0.1" }, cfg.Addresses);
            Assert.Equal(655, cfg.Port);
            Assert.Equal(new[] { "10.9.0.0/24" }, cfg.Subnets);
        }

        [Fact]
        public void HostConfig_Base64RoundTrip()
        {
            byte[] key = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(key);
            string b64 = TincHostConfig.EncodeBase64Key(key);
            byte[] decoded = TincHostConfig.DecodeBase64Key(b64);
            Assert.Equal(key, decoded);
        }
    }
}
