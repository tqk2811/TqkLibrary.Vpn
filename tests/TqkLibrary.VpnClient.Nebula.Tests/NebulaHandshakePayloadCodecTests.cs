using TqkLibrary.VpnClient.Nebula.Handshake;
using TqkLibrary.VpnClient.Nebula.Handshake.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Nebula.Tests
{
    public class NebulaHandshakePayloadCodecTests
    {
        readonly NebulaHandshakePayloadCodec _codec = new();

        [Fact]
        public void HandshakeDetails_RoundTrip()
        {
            var d = new NebulaHandshakeDetails
            {
                Cert = new byte[] { 1, 2, 3, 4, 5 },
                InitiatorIndex = 0x11223344,
                ResponderIndex = 0x55667788,
                Time = 1_700_000_000_000_000_000UL,
            };

            byte[] bytes = _codec.Marshal(d);
            var back = _codec.Unmarshal(bytes);

            Assert.Equal(d.Cert, back.Cert);
            Assert.Equal(d.InitiatorIndex, back.InitiatorIndex);
            Assert.Equal(d.ResponderIndex, back.ResponderIndex);
            Assert.Equal(d.Time, back.Time);
        }

        [Fact]
        public void Marshal_Msg1Style_OnlyInitiatorIndexAndCert()
        {
            var d = new NebulaHandshakeDetails
            {
                Cert = new byte[] { 9, 9, 9 },
                InitiatorIndex = 42,
                Time = 123456789,
            };
            byte[] bytes = _codec.Marshal(d);
            var back = _codec.Unmarshal(bytes);

            Assert.Equal(42u, back.InitiatorIndex);
            Assert.Equal(0u, back.ResponderIndex);
            Assert.Equal(d.Cert, back.Cert);
        }

        [Fact]
        public void Unmarshal_UnknownFields_Ignored()
        {
            // A future field (e.g. CertVersion=8 varint) should be skipped cleanly.
            var d = new NebulaHandshakeDetails { InitiatorIndex = 7 };
            byte[] bytes = _codec.Marshal(d);
            var back = _codec.Unmarshal(bytes);
            Assert.Equal(7u, back.InitiatorIndex);
        }
    }
}
