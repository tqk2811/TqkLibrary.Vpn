using TqkLibrary.VpnClient.OpenVpn.Config;
using TqkLibrary.VpnClient.OpenVpn.Enums;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>Checks that the .ovpn parser maps the common directives + inline blocks into an OpenVpnProfile.</summary>
    public class OpenVpnConfigParserTests
    {
        const string FullProfile = @"
# a typical client profile
client
dev tun
proto udp
remote vpn.example.com 1194
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256
auth-user-pass
remote-cert-tls server
comp-lzo no
key-direction 1
reneg-sec 3600
tun-mtu 1500
; a comment line
<ca>
-----BEGIN CERTIFICATE-----
MIICA
-----END CERTIFICATE-----
</ca>
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
0123456789abcdef
-----END OpenVPN Static key V1-----
</tls-auth>
x-custom-directive foo bar
";

        [Fact]
        public void Parse_FullProfile_MapsCommonDirectives()
        {
            OpenVpnProfile p = OpenVpnConfigParser.Parse(FullProfile);

            Assert.True(p.IsClient);
            Assert.Equal(OpenVpnDeviceType.Tun, p.Device);
            Assert.Equal(OpenVpnProtocol.Udp, p.Protocol);

            OpenVpnRemote remote = Assert.Single(p.Remotes);
            Assert.Equal("vpn.example.com", remote.Host);
            Assert.Equal(1194, remote.Port);
            Assert.Null(remote.Protocol);

            Assert.Equal("AES-256-GCM", p.Cipher);
            Assert.Equal(new[] { "AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305" }, p.DataCiphers);
            Assert.Equal("SHA256", p.Auth);
            Assert.True(p.AuthUserPass);
            Assert.True(p.RemoteCertTlsServer);
            Assert.Equal("no", p.Compression);
            Assert.Equal(1, p.KeyDirection);
            Assert.Equal(3600, p.RenegSec);
            Assert.Equal(1500, p.TunMtu);
        }

        [Fact]
        public void Parse_InlineBlocks_KeptAsPemVerbatim()
        {
            OpenVpnProfile p = OpenVpnConfigParser.Parse(FullProfile);

            Assert.NotNull(p.Ca);
            Assert.True(p.Ca!.IsInline);
            Assert.Contains("BEGIN CERTIFICATE", p.Ca.Inline);
            Assert.Contains("MIICA", p.Ca.Inline);
            Assert.Null(p.Ca.FilePath);

            Assert.NotNull(p.TlsAuth);
            Assert.True(p.TlsAuth!.IsInline);
            Assert.Contains("OpenVPN Static key V1", p.TlsAuth.Inline);
        }

        [Fact]
        public void Parse_UnknownDirective_PreservedVerbatim()
        {
            OpenVpnProfile p = OpenVpnConfigParser.Parse(FullProfile);

            Assert.True(p.OtherDirectives.ContainsKey("x-custom-directive"));
            string[] args = Assert.Single(p.OtherDirectives["x-custom-directive"]);
            Assert.Equal(new[] { "foo", "bar" }, args);
        }

        [Fact]
        public void Parse_FilePathForm_RecordsPathNotInline()
        {
            OpenVpnProfile p = OpenVpnConfigParser.Parse("ca /etc/openvpn/ca.crt\ncert client.crt\nkey client.key\ntls-auth ta.key 1");

            Assert.Equal("/etc/openvpn/ca.crt", p.Ca!.FilePath);
            Assert.False(p.Ca.IsInline);
            Assert.Equal("client.crt", p.Cert!.FilePath);
            Assert.Equal("client.key", p.Key!.FilePath);
            Assert.Equal("ta.key", p.TlsAuth!.FilePath);
            Assert.Equal(1, p.KeyDirection); // third arg of tls-auth
        }

        [Fact]
        public void Parse_MultipleRemotes_WithPerRemotePortAndProto()
        {
            OpenVpnProfile p = OpenVpnConfigParser.Parse(
                "port 1300\nremote a.example.com\nremote b.example.com 443 tcp\nremote c.example.com 1195");

            Assert.Equal(3, p.Remotes.Count);
            Assert.Equal("a.example.com", p.Remotes[0].Host);
            Assert.Equal(1300, p.Remotes[0].Port);              // inherits the `port` default
            Assert.Null(p.Remotes[0].Protocol);

            Assert.Equal(443, p.Remotes[1].Port);
            Assert.Equal(OpenVpnProtocol.Tcp, p.Remotes[1].Protocol);

            Assert.Equal(1195, p.Remotes[2].Port);
        }

        [Fact]
        public void Parse_TcpProtoAndQuotedArgs()
        {
            OpenVpnProfile p = OpenVpnConfigParser.Parse("proto tcp-client\nverify-x509-name \"My Server CN\" name");

            Assert.Equal(OpenVpnProtocol.Tcp, p.Protocol);
            string[] args = Assert.Single(p.OtherDirectives["verify-x509-name"]);
            Assert.Equal(new[] { "My Server CN", "name" }, args);
        }

        [Fact]
        public void Parse_InlineWinsOverFilePathRegardlessOfOrder()
        {
            // file directive after the inline block, and before — inline must win both ways.
            OpenVpnProfile after = OpenVpnConfigParser.Parse("<ca>\nINLINE-PEM\n</ca>\nca ca.crt");
            Assert.True(after.Ca!.IsInline);
            Assert.Equal("INLINE-PEM", after.Ca.Inline);

            OpenVpnProfile before = OpenVpnConfigParser.Parse("ca ca.crt\n<ca>\nINLINE-PEM\n</ca>");
            Assert.True(before.Ca!.IsInline);
            Assert.Equal("INLINE-PEM", before.Ca.Inline);
        }

        [Fact]
        public void Parse_ConnectionBlock_IsFlattened()
        {
            OpenVpnProfile p = OpenVpnConfigParser.Parse(
                "<connection>\nremote inside.example.com 1234 udp\n</connection>\nremote outside.example.com 5678");

            Assert.Equal(2, p.Remotes.Count);
            Assert.Equal("inside.example.com", p.Remotes[0].Host);
            Assert.Equal(1234, p.Remotes[0].Port);
            Assert.Equal(OpenVpnProtocol.Udp, p.Remotes[0].Protocol);
            Assert.Equal("outside.example.com", p.Remotes[1].Host);
        }
    }
}
