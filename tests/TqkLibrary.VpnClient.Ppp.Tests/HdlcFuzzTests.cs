using TqkLibrary.VpnClient.Ppp.Framing;
using Xunit;

namespace TqkLibrary.VpnClient.Ppp.Tests
{
    /// <summary>
    /// Malformed-input fuzzing for the HDLC-async PPP decoder (RFC 1662). Pushes random byte streams — including
    /// dense flag/escape sequences and arbitrary chunk splits — and asserts the decoder never throws and never hangs,
    /// silently dropping frames with a bad FCS. Deterministic (fixed RNG seed).
    /// </summary>
    public class HdlcFuzzTests
    {
        [Fact]
        public async Task Push_NeverThrowsOrHangs_OnGarbage()
        {
            Task fuzz = Task.Run(Drive);
            Task winner = await Task.WhenAny(fuzz, Task.Delay(TimeSpan.FromSeconds(30)));
            Assert.True(winner == fuzz, "the HDLC decoder appears to hang on malformed input");
            await fuzz;
        }

        static void Drive()
        {
            var rng = new Random(0x1662); // RFC 1662
            for (int i = 0; i < 4000; i++)
            {
                var decoder = new HdlcDecoder();
                int frames = 0;
                decoder.FrameReceived += _ => frames++;

                byte[] data = new byte[rng.Next(0, 400)];
                rng.NextBytes(data);
                // Bias toward flags (0x7E) and escapes (0x7D) so frame boundaries and un-stuffing get exercised.
                for (int j = 0; j < data.Length; j++)
                {
                    int r = rng.Next(0, 10);
                    if (r == 0) data[j] = 0x7E;
                    else if (r == 1) data[j] = 0x7D;
                }

                // Feed in random-sized chunks to exercise the streaming state across calls.
                int offset = 0;
                while (offset < data.Length)
                {
                    int chunk = Math.Min(data.Length - offset, rng.Next(1, 17));
                    decoder.Push(data.AsSpan(offset, chunk));
                    offset += chunk;
                }
                _ = frames; // observed; garbage almost never yields a valid FCS, which is fine
            }
        }
    }
}
