using TqkLibrary.Vpn.L2tp;
using Xunit;

namespace TqkLibrary.Vpn.L2tp.Tests
{
    /// <summary>
    /// Malformed-input fuzzing for the L2TPv2 codec (header + AVP walk). Asserts the decoders terminate quickly and
    /// only ever throw controlled exceptions on garbage — they must not hang on a bad AVP length or surface an
    /// unexpected exception type. Deterministic (fixed RNG seed).
    /// </summary>
    public class L2tpCodecFuzzTests
    {
        [Fact]
        public async Task Decoders_TerminateAndThrowControlled_OnGarbage()
        {
            Task fuzz = Task.Run(Drive);
            Task winner = await Task.WhenAny(fuzz, Task.Delay(TimeSpan.FromSeconds(30)));
            Assert.True(winner == fuzz, "an L2TP decoder appears to hang on malformed input");
            await fuzz;
        }

        static void Drive()
        {
            for (int n = 0; n <= 40; n++) Feed(new byte[n]);

            var rng = new Random(0x2661); // RFC 2661
            for (int i = 0; i < 6000; i++)
            {
                byte[] data = new byte[rng.Next(0, 300)];
                rng.NextBytes(data);
                Feed(data);
            }

            // Force the control-message header flags (T/L/S) so the AVP walk runs against random AVP lengths.
            for (int i = 0; i < 4000; i++)
            {
                byte[] data = new byte[rng.Next(12, 200)];
                rng.NextBytes(data);
                data[0] = 0xC8; // T=1, L=1, S=1
                data[1] = 0x02; // version 2
                Feed(data);
            }
        }

        static void Feed(byte[] data)
        {
            Try(() => L2tpCodec.IsControl(data));
            Try(() => L2tpCodec.DecodeControl(data));
            Try(() => L2tpCodec.TryDecodeData(data, out _, out _, out _));
        }

        static void Try(Action action)
        {
            try { action(); }
            catch (Exception ex) when (
                ex is ArgumentException or IndexOutOfRangeException or OverflowException
                or FormatException or InvalidOperationException or NotSupportedException)
            {
                // expected for malformed input
            }
        }
    }
}
