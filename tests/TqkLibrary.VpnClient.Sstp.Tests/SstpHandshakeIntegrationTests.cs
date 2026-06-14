using TqkLibrary.VpnClient.Drivers.Sstp;
using TqkLibrary.VpnClient.Drivers.Sstp.Enums;
using TqkLibrary.VpnClient.Drivers.Sstp.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Sstp.Tests
{
    /// <summary>
    /// Live integration test against a public VPN Gate SSTP server. Requires outbound TLS to :443 and a
    /// reachable server, so it is tagged Integration. Validates the SSTP transport + control handshake.
    /// </summary>
    [Trait("Category", "Integration")]
    public class SstpHandshakeIntegrationTests
    {
        const string Host = "public-vpn-227.opengw.net";

        [Fact]
        public async Task Connects_And_ReceivesCallConnectAck()
        {
            using var transport = new SstpTransport(Host, 443);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

            await transport.ConnectAsync(cts.Token);
            Assert.NotNull(transport.ServerCertificate);

            var encapsulatedProtocol = new SstpAttribute(
                (byte)SstpAttributeId.EncapsulatedProtocolId,
                new byte[] { 0x00, 0x01 }); // PPP
            await transport.SendControlAsync(SstpMessageType.CallConnectRequest, new[] { encapsulatedProtocol }, cts.Token);

            (bool isControl, byte[] body) = await transport.ReadPacketAsync(cts.Token);
            Assert.True(isControl);

            SstpControlMessage message = SstpControlCodec.Parse(body);
            Assert.Equal(SstpMessageType.CallConnectAck, message.MessageType);

            SstpAttribute? cryptoBindingReq = message.Find(SstpAttributeId.CryptoBindingReq);
            Assert.NotNull(cryptoBindingReq);
            // Crypto Binding Request value = Reserved(3) + HashProtocolBitmask(1) + Nonce(32) = 36 bytes.
            Assert.True(cryptoBindingReq!.Value.Length >= 4 + SstpConstants.NonceLength,
                $"unexpected crypto-binding-request length {cryptoBindingReq.Value.Length}");
        }
    }
}
