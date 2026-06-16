using TqkLibrary.VpnClient.Drivers.Sstp;
using TqkLibrary.VpnClient.Drivers.Sstp.Enums;
using TqkLibrary.VpnClient.Drivers.Sstp.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Sstp.Tests
{
    /// <summary>
    /// Offline unit + fuzz coverage for <see cref="SstpControlCodec"/> — the control-message codec the keepalive,
    /// teardown and crypto-binding paths all depend on. Pins the BuildBody↔Parse round-trip and checks Parse never
    /// hangs or throws an uncontrolled exception on malformed input.
    /// </summary>
    public class SstpControlCodecTests
    {
        [Fact]
        public void BuildBody_Then_Parse_RoundTripsTypeAndAttributes()
        {
            var attributes = new[]
            {
                new SstpAttribute((byte)SstpAttributeId.EncapsulatedProtocolId, new byte[] { 0x00, 0x01 }),
                new SstpAttribute((byte)SstpAttributeId.CryptoBinding, Sequence(100)), // a realistic 100-byte binding value
            };

            byte[] body = SstpControlCodec.BuildBody(SstpMessageType.CallConnected, attributes);
            SstpControlMessage parsed = SstpControlCodec.Parse(body);

            Assert.Equal(SstpMessageType.CallConnected, parsed.MessageType);
            Assert.Equal(2, parsed.Attributes.Count);
            Assert.Equal((byte)SstpAttributeId.EncapsulatedProtocolId, parsed.Attributes[0].Id);
            Assert.Equal(new byte[] { 0x00, 0x01 }, parsed.Attributes[0].Value);
            Assert.Equal((byte)SstpAttributeId.CryptoBinding, parsed.Attributes[1].Id);
            Assert.Equal(Sequence(100), parsed.Attributes[1].Value);
        }

        [Fact]
        public void Parse_RoundTrips_EmptyAttributeMessage()
        {
            byte[] body = SstpControlCodec.BuildBody(SstpMessageType.EchoRequest, Array.Empty<SstpAttribute>());
            SstpControlMessage parsed = SstpControlCodec.Parse(body);

            Assert.Equal(SstpMessageType.EchoRequest, parsed.MessageType);
            Assert.Empty(parsed.Attributes);
        }

        [Fact]
        public async Task Parse_TerminatesAndThrowsControlled_OnGarbage()
        {
            Task fuzz = Task.Run(Drive);
            Task winner = await Task.WhenAny(fuzz, Task.Delay(TimeSpan.FromSeconds(30)));
            Assert.True(winner == fuzz, "SstpControlCodec.Parse appears to hang on malformed input");
            await fuzz;
        }

        static void Drive()
        {
            for (int n = 0; n <= 16; n++) TryParse(new byte[n]);

            var rng = new Random(0x5512); // SSTP-ish
            for (int i = 0; i < 5000; i++)
            {
                byte[] data = new byte[rng.Next(0, 256)];
                rng.NextBytes(data);
                TryParse(data);
            }

            // Header that claims many attributes but with random (often inconsistent) attribute lengths.
            for (int i = 0; i < 3000; i++)
            {
                byte[] data = new byte[rng.Next(4, 128)];
                rng.NextBytes(data);
                data[2] = 0xFF; data[3] = 0xFF; // numAttributes = 65535
                TryParse(data);
            }
        }

        static void TryParse(byte[] data)
        {
            try { SstpControlCodec.Parse(data); }
            catch (Exception ex) when (
                ex is ArgumentException or IndexOutOfRangeException or OverflowException
                or FormatException or InvalidOperationException or NotSupportedException)
            {
                // expected for malformed input
            }
        }

        static byte[] Sequence(int length)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++) b[i] = (byte)i;
            return b;
        }
    }
}
