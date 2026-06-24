using System.Text;
using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.Drivers.Nebula.DataChannel;
using TqkLibrary.VpnClient.Nebula.Handshake;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.Nebula.Tests
{
    /// <summary>
    /// Unit tests for the Nebula data-plane transport (message-packet seal/open + anti-replay) in isolation, paired
    /// with a second transport oriented the other way (the crossed transport keys from a Noise IX Split).
    /// </summary>
    public class NebulaTransportTests
    {
        static (NebulaTransport client, NebulaTransport server, uint clientIndex, uint serverIndex) BuildPair()
        {
            byte[] initStatic = new Curve25519DhGroup().GeneratePrivateKey();
            byte[] respStatic = new Curve25519DhGroup().GeneratePrivateKey();
            var initiator = new NebulaNoiseIxHandshake(initStatic);
            var responder = new NebulaNoiseIxHandshake(respStatic);

            byte[] msg1 = initiator.CreateInitiation(Array.Empty<byte>());
            Assert.True(responder.ConsumeInitiation(msg1, out _));
            byte[] msg2 = responder.CreateResponse(Array.Empty<byte>());
            Assert.True(initiator.ConsumeResponse(msg2, out _));

            (byte[] iSend, byte[] iRecv) = initiator.Split();
            (byte[] rSend, byte[] rRecv) = responder.Split();

            const uint clientIndex = 0x11112222;
            const uint serverIndex = 0x33334444;
            // Each side seals with the PEER's index (so the peer can route), opens with its own.
            var client = new NebulaTransport(iSend, iRecv, sendRemoteIndex: serverIndex, localIndex: clientIndex);
            var server = new NebulaTransport(rSend, rRecv, sendRemoteIndex: clientIndex, localIndex: serverIndex);
            return (client, server, clientIndex, serverIndex);
        }

        [Fact]
        public void Seal_Open_RoundTripsBothDirections()
        {
            var (client, server, _, _) = BuildPair();

            byte[] toServer = Encoding.ASCII.GetBytes("inner IP packet client->server");
            byte[] wire1 = client.Seal(toServer);
            Assert.True(server.TryOpen(wire1, out byte[] got1));
            Assert.Equal(toServer, got1);

            byte[] toClient = Encoding.ASCII.GetBytes("inner IP packet server->client");
            byte[] wire2 = server.Seal(toClient);
            Assert.True(client.TryOpen(wire2, out byte[] got2));
            Assert.Equal(toClient, got2);
        }

        [Fact]
        public void TryOpen_TamperedTag_Rejected()
        {
            var (client, server, _, _) = BuildPair();
            byte[] wire = client.Seal(Encoding.ASCII.GetBytes("payload"));
            wire[^1] ^= 0xFF; // corrupt the AEAD tag
            Assert.False(server.TryOpen(wire, out _));
        }

        [Fact]
        public void TryOpen_WrongIndex_Rejected()
        {
            var (client, server, clientIndex, _) = BuildPair();
            // A transport that opens with the wrong local index (not the one stamped on the wire) must reject it.
            byte[] wire = client.Seal(Encoding.ASCII.GetBytes("payload"));
            var stranger = new NebulaTransport(new byte[32], new byte[32], sendRemoteIndex: 0, localIndex: clientIndex + 1);
            Assert.False(stranger.TryOpen(wire, out _));
            Assert.True(server.TryOpen(wire, out _)); // the right index still works
        }

        [Fact]
        public void TryOpen_Replay_Rejected()
        {
            var (client, server, _, _) = BuildPair();
            byte[] wire = client.Seal(Encoding.ASCII.GetBytes("once"));
            Assert.True(server.TryOpen(wire, out _));
            Assert.False(server.TryOpen(wire, out _)); // same counter again ⇒ replay
        }

        [Fact]
        public void Counters_AreMonotonicStartingAtOne()
        {
            var (client, server, _, _) = BuildPair();
            Assert.Equal(0UL, client.SentPacketCount);
            client.Seal(Encoding.ASCII.GetBytes("a"));
            Assert.Equal(1UL, client.SentPacketCount);
            byte[] w = client.Seal(Encoding.ASCII.GetBytes("b"));
            Assert.Equal(2UL, client.SentPacketCount);
            Assert.True(server.TryOpen(w, out _));
            Assert.Equal(2UL, server.HighestReceivedCounter); // second packet has counter 2
        }
    }
}
