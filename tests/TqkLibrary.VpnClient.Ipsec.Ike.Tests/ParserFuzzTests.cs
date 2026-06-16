using TqkLibrary.VpnClient.Ipsec.Ike.V1;
using TqkLibrary.VpnClient.Ipsec.Ike.V2;
using Xunit;

namespace TqkLibrary.VpnClient.Ipsec.Ike.Tests
{
    /// <summary>
    /// Malformed-input fuzzing for the IKE codecs. Feeds empty / truncated / random / structurally-bogus bytes into
    /// the decoders and asserts they always terminate quickly and only ever throw controlled (argument/index/format)
    /// exceptions — never hang, corrupt, or surface an unexpected exception type. Deterministic (fixed RNG seed).
    /// </summary>
    public class ParserFuzzTests
    {
        [Fact]
        public Task IsakmpMessage_Decode_TerminatesAndThrowsControlled()
            => ParserFuzz.Run(data => IsakmpMessage.Decode(data), validHeaderSize: 28);

        [Fact]
        public Task IkeMessage_Decode_TerminatesAndThrowsControlled()
            => ParserFuzz.Run(data => IkeMessage.Decode(data), validHeaderSize: 28);
    }

    /// <summary>Shared fuzz harness: drives <paramref name="parse"/> with many malformed inputs under a hang guard.</summary>
    internal static class ParserFuzz
    {
        public static async Task Run(Action<byte[]> parse, int validHeaderSize)
        {
            Task fuzz = Task.Run(() => Drive(parse, validHeaderSize));
            // A controlled run finishes in well under a second; a hang (unbounded parser loop) trips this.
            Task winner = await Task.WhenAny(fuzz, Task.Delay(TimeSpan.FromSeconds(30)));
            Assert.True(winner == fuzz, "the parser appears to hang on malformed input");
            await fuzz; // re-throw any unexpected (non-controlled) exception
        }

        static void Drive(Action<byte[]> parse, int validHeaderSize)
        {
            // Empty and tiny inputs.
            for (int n = 0; n <= validHeaderSize + 8; n++)
                TryParse(parse, new byte[n]);

            // Random garbage of varied lengths (fixed seed → reproducible).
            var rng = new Random(0x15AC); // "ISAC"-ish
            for (int i = 0; i < 4000; i++)
            {
                byte[] data = new byte[rng.Next(0, 600)];
                rng.NextBytes(data);
                TryParse(parse, data);
            }

            // Plausible header + random body (exercises the payload-chain walk and typed-payload parsers).
            for (int i = 0; i < 2000; i++)
            {
                byte[] data = new byte[validHeaderSize + rng.Next(0, 400)];
                rng.NextBytes(data);
                // Make the declared length field roughly consistent so the chain walk runs deeper.
                data[24] = (byte)(data.Length >> 24); data[25] = (byte)(data.Length >> 16);
                data[26] = (byte)(data.Length >> 8); data[27] = (byte)data.Length;
                TryParse(parse, data);
            }
        }

        static void TryParse(Action<byte[]> parse, byte[] data)
        {
            try { parse(data); }
            catch (Exception ex) when (IsControlled(ex)) { /* expected for malformed input */ }
        }

        static bool IsControlled(Exception ex) =>
            ex is ArgumentException            // includes ArgumentOutOfRange / ArgumentNull
            or IndexOutOfRangeException
            or OverflowException
            or FormatException
            or InvalidOperationException
            or NotSupportedException;
    }
}
