using System;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Drivers.Tailscale;
using TqkLibrary.VpnClient.Drivers.Tailscale.Config;
using TqkLibrary.VpnClient.Tailscale.Control;
using TqkLibrary.VpnClient.Tailscale.Control.Messages;
using TqkLibrary.VpnClient.Tailscale.Keys;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.Tailscale.Tests
{
    public class TailscaleDriverTests
    {
        static TailscaleConfig SampleConfig() =>
            TailscaleConfig.Generate(new Uri("http://headscale:8080"), "preauth-abc", hostname: "lab");

        static byte[] Random32()
        {
            var b = new byte[32];
            new Random(1234).NextBytes(b);
            return b;
        }

        [Fact]
        public void Capabilities_AreL3_Udp_Noise_PreSharedKey_RoutedPrefixes_OutOfBand()
        {
            var driver = new TailscaleDriver(SampleConfig());
            Assert.Equal("tailscale", driver.Name);
            var caps = driver.Capabilities;
            Assert.Equal(VpnLinkLayer.L3Ip, caps.LinkLayer);
            Assert.False(caps.UsesPpp);
            Assert.Equal(MultiHostModel.RoutedPrefixes, caps.MultiHostModel);
            Assert.Equal(VpnTransportKind.Udp, caps.TransportKinds);
            Assert.Equal(VpnSecurityKind.Noise, caps.SecurityKinds);
            Assert.Equal(VpnAuthMethod.PreSharedKey, caps.AuthMethods);
            Assert.Equal(AddressAssignment.OutOfBand, caps.AddressAssignment);
        }

        [Fact]
        public void Config_Generate_ProducesTwoDistinct32ByteKeys()
        {
            TailscaleConfig cfg = SampleConfig();
            Assert.Equal(32, cfg.MachinePrivateKey.Length);
            Assert.Equal(32, cfg.NodePrivateKey.Length);
            Assert.NotEqual(cfg.MachinePrivateKey, cfg.NodePrivateKey);
        }

        [Fact]
        public async Task Connect_NetmapWithNoUsablePeers_Throws()
        {
            // A netmap whose only peer has no direct endpoint → mapping drops it → no peers → driver throws.
            var map = new MapResponse
            {
                Node = new TailscaleNode { ID = 1, Key = TailscaleKey.EncodeNodePublic(Random32()), Addresses = new[] { "100.64.0.1/32" } },
                Peers = new[]
                {
                    new TailscaleNode { ID = 2, Key = TailscaleKey.EncodeNodePublic(Random32()), AllowedIPs = new[] { "100.64.0.2/32" }, Endpoints = Array.Empty<string>() },
                },
            };
            var fake = new FakeTailscaleControlClient(map);
            var driver = new TailscaleDriver(SampleConfig(), controlClientFactory: _ => fake);

            await Assert.ThrowsAnyAsync<Exception>(async () =>
                await driver.ConnectAsync(new Abstractions.Drivers.Models.VpnEndpoint("headscale", 8080),
                    new Abstractions.Drivers.Models.VpnCredentials(), new CancellationTokenSource(TimeSpan.FromSeconds(5)).Token));

            Assert.Equal("preauth-abc", fake.LastPreauthKey); // login ran with the configured preauth key
            Assert.True(fake.Disposed);                       // control client cleaned up
        }

        [Fact]
        public async Task Connect_ControlError_Propagates()
        {
            var fake = new FakeTailscaleControlClient(new TailscaleControlException("invalid pre auth key"));
            var driver = new TailscaleDriver(SampleConfig(), controlClientFactory: _ => fake);

            var ex = await Assert.ThrowsAnyAsync<Exception>(async () =>
                await driver.ConnectAsync(new Abstractions.Drivers.Models.VpnEndpoint("headscale", 8080),
                    new Abstractions.Drivers.Models.VpnCredentials(), CancellationToken.None));
            Assert.Contains("invalid pre auth key", FlattenMessages(ex));
        }

        static string FlattenMessages(Exception ex)
        {
            string s = ex.Message;
            while (ex.InnerException is not null) { ex = ex.InnerException; s += " | " + ex.Message; }
            return s;
        }
    }
}
