using Xunit;

namespace TqkLibrary.VpnClient.Drivers.L2tpIpsec.Tests
{
    public class L2tpIpsecReconnectOptionsTests
    {
        [Fact]
        public void Defaults_EnableReconnectWithSaneBackoff()
        {
            var options = new L2tpIpsecReconnectOptions();

            Assert.True(options.Enabled);
            Assert.Equal(0, options.MaxAttempts); // infinite until DisconnectAsync
            Assert.Equal(TimeSpan.FromSeconds(1), options.InitialBackoff);
            Assert.Equal(TimeSpan.FromSeconds(30), options.MaxBackoff);
            Assert.Equal(2.0, options.BackoffMultiplier);
        }

        [Fact]
        public void NextBackoff_GrowsGeometrically_ThenCapsAtMax()
        {
            var options = new L2tpIpsecReconnectOptions
            {
                InitialBackoff = TimeSpan.FromSeconds(1),
                MaxBackoff = TimeSpan.FromSeconds(8),
                BackoffMultiplier = 2.0,
            };

            TimeSpan delay = options.InitialBackoff;
            Assert.Equal(TimeSpan.FromSeconds(2), delay = options.NextBackoff(delay));
            Assert.Equal(TimeSpan.FromSeconds(4), delay = options.NextBackoff(delay));
            Assert.Equal(TimeSpan.FromSeconds(8), delay = options.NextBackoff(delay));
            Assert.Equal(TimeSpan.FromSeconds(8), options.NextBackoff(delay)); // capped at MaxBackoff
        }
    }
}
