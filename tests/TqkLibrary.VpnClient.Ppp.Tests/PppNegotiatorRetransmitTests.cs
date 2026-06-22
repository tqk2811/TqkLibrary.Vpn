using System.Linq;
using TqkLibrary.VpnClient.Ppp;
using TqkLibrary.VpnClient.Ppp.Enums;
using TqkLibrary.VpnClient.Ppp.Models;
using Xunit;

namespace TqkLibrary.VpnClient.Ppp.Tests
{
    /// <summary>
    /// Offline coverage for the RFC 1661 §4.6 Restart timer in <see cref="PppNegotiator"/>: an unanswered
    /// Configure-Request must be retransmitted verbatim (so a lost request — or one a peer drops because its own
    /// layer is not yet up, e.g. accel-ppp/SSTP IPCP before NPMODE_PASS — no longer stalls the link), and the
    /// retransmission must stop the moment our request is acknowledged.
    /// </summary>
    public class PppNegotiatorRetransmitTests
    {
        [Fact]
        public async Task UnansweredConfigureRequest_IsRetransmittedVerbatim()
        {
            var gate = new object();
            var sent = new List<byte[]>();
            using var neg = new TestNegotiator(p => { lock (gate) sent.Add(p); }, TimeSpan.FromMilliseconds(40));

            neg.Start();                       // first Configure-Request
            await Task.Delay(200);             // no response → the Restart timer must resend it

            byte[][] snapshot;
            lock (gate) snapshot = sent.ToArray();

            Assert.True(snapshot.Length >= 2, $"expected the unanswered Configure-Request to be retransmitted, saw {snapshot.Length} send(s)");
            PppControlPacket[] parsed = snapshot.Select(p => PppControlCodec.Parse(p)).ToArray();
            Assert.All(parsed, p => Assert.Equal((byte)PppCode.ConfigureRequest, p.Code));
            Assert.All(parsed, p => Assert.Equal(parsed[0].Identifier, p.Identifier)); // verbatim: same Identifier each time
        }

        [Fact]
        public async Task AcknowledgedConfigureRequest_StopsRetransmission()
        {
            var gate = new object();
            var sent = new List<byte[]>();
            using var neg = new TestNegotiator(p => { lock (gate) sent.Add(p); }, TimeSpan.FromMilliseconds(40));

            neg.Start();
            byte requestId;
            lock (gate) requestId = PppControlCodec.Parse(sent[0]).Identifier;

            // Acknowledge our request before the first retransmit fires → the timer must stop.
            neg.HandlePacket(PppControlCodec.BuildConfigure((byte)PppCode.ConfigureAck, requestId, System.Array.Empty<PppOption>()));
            int countAtAck;
            lock (gate) countAtAck = sent.Count;

            await Task.Delay(200);             // well past several Restart intervals
            int finalCount;
            lock (gate) finalCount = sent.Count;

            Assert.Equal(countAtAck, finalCount); // no further Configure-Requests after the Ack
        }

        // A minimal concrete negotiator: requests one trivial option and acks whatever the peer requests.
        sealed class TestNegotiator : PppNegotiator
        {
            public TestNegotiator(Action<byte[]> send, TimeSpan interval) : base(send, interval, maxRequests: 100) { }

            protected override IReadOnlyList<PppOption> BuildLocalOptions()
                => new[] { new PppOption(1, new byte[] { 0x00 }) };

            protected override (byte code, IReadOnlyList<PppOption> options) EvaluatePeerRequest(List<PppOption> peerOptions)
                => ((byte)PppCode.ConfigureAck, peerOptions);
        }
    }
}
