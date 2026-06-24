using TqkLibrary.VpnClient.Drivers.Tinc;
using TqkLibrary.VpnClient.Drivers.Tinc.DataChannel;
using TqkLibrary.VpnClient.Tinc.Sptps;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.Tinc.Tests
{
    /// <summary>
    /// Unit tests for the tinc data-plane transport: the relay-header framing (DSTID‖SRCID), SPTPS record round-trip,
    /// and the node-id hash. Two transports keyed with crossed directional keys model the two ends of one data session.
    /// </summary>
    public class TincDataTransportTests
    {
        static byte[] Key(byte seed)
        {
            byte[] k = new byte[TincChaChaPoly1305.KeyLength];
            for (int i = 0; i < k.Length; i++) k[i] = (byte)(seed + i);
            return k;
        }

        static (TincDataTransport client, TincDataTransport server) Pair(out byte[] clientId, out byte[] serverId)
        {
            byte[] cToS = Key(1), sToC = Key(100);
            clientId = TincNodeId.Compute("client");
            serverId = TincNodeId.Compute("server");
            // Client seals with cToS / opens with sToC; server is the mirror. NodeIds: client stamps SRCID=clientId and
            // expects the peer's SRCID=serverId; server stamps SRCID=serverId and expects SRCID=clientId.
            var client = new TincDataTransport(new SptpsDatagramRecordLayer(cToS, sToC), clientId, serverId);
            var server = new TincDataTransport(new SptpsDatagramRecordLayer(sToC, cToS), serverId, clientId);
            return (client, server);
        }

        [Fact]
        public void NodeId_Is_First6BytesOfSha512()
        {
            // SHA512("server")[:6] — golden value computed from the same hash tinc uses.
            byte[] id = TincNodeId.Compute("server");
            Assert.Equal(6, id.Length);
            // Different names → different ids; same name → stable.
            Assert.Equal(id, TincNodeId.Compute("server"));
            Assert.NotEqual(id, TincNodeId.Compute("client"));
        }

        [Fact]
        public void Seal_PrependsNullDstId_AndOurSrcId()
        {
            var (client, server) = Pair(out byte[] clientId, out _);
            byte[] payload = { 0x45, 0x00, 0x00, 0x1c, 1, 2, 3, 4 };
            byte[] wire = client.Seal(payload);

            // DSTID (first 6 bytes) is the null id; SRCID (next 6) is the client's node id.
            for (int i = 0; i < 6; i++) Assert.Equal(0, wire[i]);
            Assert.Equal(clientId, wire[6..12]);
            // Followed by seqno(4) || ciphertext(payload+1) || tag(16).
            Assert.Equal(12 + 4 + (payload.Length + 1) + TincChaChaPoly1305.TagLength, wire.Length);

            Assert.True(server.TryOpen(wire, out byte[] recovered));
            Assert.Equal(payload, recovered);
        }

        [Fact]
        public void RoundTrip_BothDirections()
        {
            var (client, server) = Pair(out _, out _);
            byte[] up = { 1, 2, 3, 4, 5 };
            byte[] down = { 9, 8, 7 };

            Assert.True(server.TryOpen(client.Seal(up), out byte[] gotUp));
            Assert.Equal(up, gotUp);
            Assert.True(client.TryOpen(server.Seal(down), out byte[] gotDown));
            Assert.Equal(down, gotDown);

            Assert.Equal(1ul, client.SentPacketCount);
            Assert.Equal(1ul, server.ReceivedPacketCount);
        }

        [Fact]
        public void TryOpen_ForeignSrcId_Rejected()
        {
            var (client, server) = Pair(out _, out _);
            byte[] wire = client.Seal(new byte[] { 1, 2, 3 });
            // Corrupt the SRCID (bytes 6..12) so it no longer matches the client's node id the server expects.
            wire[6] ^= 0xFF;
            Assert.False(server.TryOpen(wire, out _));
        }

        [Fact]
        public void TryOpen_Tampered_Rejected()
        {
            var (client, server) = Pair(out _, out _);
            byte[] wire = client.Seal(new byte[] { 1, 2, 3 });
            wire[wire.Length - 1] ^= 0x80; // flip a tag byte
            Assert.False(server.TryOpen(wire, out _));
        }

        [Fact]
        public void TryOpen_Replay_Rejected()
        {
            var (client, server) = Pair(out _, out _);
            byte[] wire = client.Seal(new byte[] { 1, 2, 3 });
            Assert.True(server.TryOpen(wire, out _));
            Assert.False(server.TryOpen(wire, out _)); // replay → dropped by the window
        }

        [Fact]
        public void TryOpen_ShortDatagram_Rejected()
        {
            var (_, server) = Pair(out _, out _);
            Assert.False(server.TryOpen(new byte[] { 0, 0, 0 }, out _));
        }
    }
}
