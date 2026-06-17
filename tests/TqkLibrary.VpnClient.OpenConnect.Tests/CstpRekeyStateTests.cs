using TqkLibrary.VpnClient.OpenConnect;
using TqkLibrary.VpnClient.OpenConnect.Enums;
using TqkLibrary.VpnClient.OpenConnect.Models;
using Xunit;

namespace TqkLibrary.VpnClient.OpenConnect.Tests
{
    /// <summary>
    /// Tests the clock-injected CSTP session-rekey timer (V.5): the parsed <c>X-CSTP-Rekey-Method</c> and the
    /// <c>X-CSTP-Rekey-Time</c> period gate, mirroring the <see cref="CstpDpdState"/> shape.
    /// </summary>
    public class CstpRekeyStateTests
    {
        [Theory]
        [InlineData("ssl", 3600, OpenConnectRekeyMethod.Ssl)]
        [InlineData("SSL", 3600, OpenConnectRekeyMethod.Ssl)]
        [InlineData("new-tunnel", 3600, OpenConnectRekeyMethod.NewTunnel)]
        [InlineData("none", 3600, OpenConnectRekeyMethod.None)]
        [InlineData("unknown", 3600, OpenConnectRekeyMethod.None)]
        [InlineData("ssl", 0, OpenConnectRekeyMethod.None)]    // a zero period disables rekey regardless of method
        [InlineData(null, 3600, OpenConnectRekeyMethod.None)]  // no method header
        public void ParsedRekeyMethod_MapsMethodAndPeriod(string? method, int time, OpenConnectRekeyMethod expected)
        {
            var info = new OpenConnectTunnelInfo { RekeyMethod = method, RekeyTime = time };
            Assert.Equal(expected, info.ParsedRekeyMethod);
        }

        [Fact]
        public void ShouldRekey_TrueOnlyAfterThePeriodElapses()
        {
            var state = new CstpRekeyState(OpenConnectRekeyMethod.NewTunnel, rekeySeconds: 60, nowMs: 1000);
            Assert.True(state.Enabled);
            Assert.False(state.ShouldRekey(1000));        // just (re-)established
            Assert.False(state.ShouldRekey(1000 + 59_000)); // 59 s — not yet due
            Assert.True(state.ShouldRekey(1000 + 60_000));  // 60 s — due

            // After a rekey completes, the timer re-arms for the next period.
            state.OnRekeyDone(1000 + 60_000);
            Assert.False(state.ShouldRekey(1000 + 60_000));
            Assert.True(state.ShouldRekey(1000 + 120_000));
        }

        [Fact]
        public void ShouldRekey_DisabledForNoneMethod()
        {
            var state = new CstpRekeyState(OpenConnectRekeyMethod.None, rekeySeconds: 60, nowMs: 0);
            Assert.False(state.Enabled);
            Assert.False(state.ShouldRekey(10 * 60_000)); // never, even far past any period
        }
    }
}
