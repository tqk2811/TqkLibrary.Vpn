using TqkLibrary.VpnClient.OpenVpn.DataChannel;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>Tests the V2.e keepalive: the ping magic and the clock-injected ping/ping-restart timing.</summary>
    public class OpenVpnKeepaliveTests
    {
        [Fact]
        public void Ping_RecognisesItsMagicOnly()
        {
            Assert.True(OpenVpnPing.IsPing(OpenVpnPing.Magic));
            Assert.False(OpenVpnPing.IsPing(new byte[] { 1, 2, 3 }));
            byte[] almost = OpenVpnPing.Magic.ToArray();
            almost[0] ^= 0xFF;
            Assert.False(OpenVpnPing.IsPing(almost));
        }

        [Fact]
        public void ShouldSendPing_FiresAfterIntervalOfSilence_ResetsOnSend()
        {
            var k = new OpenVpnKeepalive(pingSeconds: 10, pingRestartSeconds: 60, nowMs: 0);
            Assert.False(k.ShouldSendPing(5_000));
            Assert.True(k.ShouldSendPing(10_000));
            k.OnDataSent(10_000);
            Assert.False(k.ShouldSendPing(15_000));
            Assert.True(k.ShouldSendPing(20_000));
        }

        [Fact]
        public void IsPeerDead_FiresAfterRestartTimeout_ResetsOnReceive()
        {
            var k = new OpenVpnKeepalive(pingSeconds: 10, pingRestartSeconds: 60, nowMs: 0);
            Assert.False(k.IsPeerDead(30_000));
            Assert.True(k.IsPeerDead(60_000));
            k.OnDataReceived(60_000);
            Assert.False(k.IsPeerDead(90_000));
            Assert.True(k.IsPeerDead(120_000));
        }

        [Fact]
        public void ZeroValues_DisableBothSides()
        {
            var k = new OpenVpnKeepalive(pingSeconds: 0, pingRestartSeconds: 0, nowMs: 0);
            Assert.False(k.ShouldSendPing(1_000_000));
            Assert.False(k.IsPeerDead(1_000_000));
        }
    }
}
