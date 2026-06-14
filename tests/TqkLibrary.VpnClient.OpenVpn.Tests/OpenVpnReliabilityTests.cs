using TqkLibrary.VpnClient.OpenVpn;
using Xunit;

namespace TqkLibrary.VpnClient.OpenVpn.Tests
{
    /// <summary>
    /// Deterministic checks for the OpenVPN control-channel reliability layer. The send/receive windows take an
    /// explicit millisecond clock, so retransmit timing is exercised without sleeping.
    /// </summary>
    public class OpenVpnReliabilityTests
    {
        static byte[] B(params byte[] bytes) => bytes;

        // ---- send window ----

        [Fact]
        public void SendWindow_AssignsMonotonicIdsAndSendsNewPacketsImmediately()
        {
            var w = new OpenVpnReliableSendWindow();

            Assert.Equal(0u, w.Queue(B(1)));
            Assert.Equal(1u, w.Queue(B(2)));
            Assert.Equal(2u, w.NextPacketId);
            Assert.Equal(2, w.InFlight);

            var due = w.CollectDue(0);
            Assert.Equal(new uint[] { 0, 1 }, due.Select(d => d.Id).ToArray());
            // already sent at t=0 → nothing due again immediately
            Assert.Empty(w.CollectDue(1));
        }

        [Fact]
        public void SendWindow_RetransmitsAfterIntervalUntilAcked()
        {
            var w = new OpenVpnReliableSendWindow(new OpenVpnReliabilityOptions { Interval = TimeSpan.FromSeconds(1) });
            w.Queue(B(9));
            Assert.Single(w.CollectDue(0));          // initial send at t=0

            Assert.Empty(w.CollectDue(999));         // before the 1s interval
            Assert.Single(w.CollectDue(1000));       // first retransmit at t=1000
            Assert.Single(w.CollectDue(2000));       // second retransmit

            w.Acknowledge(0);                        // peer acked → cleared
            Assert.Equal(0, w.InFlight);
            Assert.Empty(w.CollectDue(3000));
        }

        [Fact]
        public void SendWindow_BackoffGrowsTheInterval()
        {
            var w = new OpenVpnReliableSendWindow(new OpenVpnReliabilityOptions
            {
                Interval = TimeSpan.FromSeconds(1),
                BackoffMultiplier = 2.0,
                MaxInterval = TimeSpan.FromSeconds(8),
            });
            w.Queue(B(1));
            w.CollectDue(0);                         // send #1 at t=0
            Assert.Single(w.CollectDue(1000));       // resend #1 after 1s (IntervalFor(0))
            Assert.Empty(w.CollectDue(2999));        // resend #2 must wait 2s (IntervalFor(1)) → at 3000
            Assert.Single(w.CollectDue(3000));
        }

        [Fact]
        public void SendWindow_IsExhausted_AfterMaxRetransmits()
        {
            var w = new OpenVpnReliableSendWindow(new OpenVpnReliabilityOptions
            {
                Interval = TimeSpan.FromSeconds(1),
                MaxRetransmits = 2, // initial + 2 resends = 3 sends total
            });
            w.Queue(B(1));
            w.CollectDue(0);                         // send 1
            w.CollectDue(1000);                      // resend 1
            w.CollectDue(2000);                      // resend 2 (budget used)
            Assert.False(w.IsExhausted(2000));
            Assert.Empty(w.CollectDue(3000));        // no more resends
            Assert.True(w.IsExhausted(3000));        // declared dead once the next interval elapses
        }

        [Fact]
        public void SendWindow_RespectsWindowSize()
        {
            var w = new OpenVpnReliableSendWindow(new OpenVpnReliabilityOptions { WindowSize = 2 });
            w.Queue(B(1));
            w.Queue(B(2));
            Assert.False(w.CanQueue);
            Assert.Throws<InvalidOperationException>(() => w.Queue(B(3)));

            w.Acknowledge(0);
            Assert.True(w.CanQueue);
            Assert.Equal(2u, w.Queue(B(3)));         // ids keep advancing, not reused
        }

        // ---- receive window ----

        [Fact]
        public void ReceiveWindow_DeliversInOrderAndQueuesAcks()
        {
            var w = new OpenVpnReliableReceiveWindow();

            Assert.True(w.Offer(0, B(10)));
            Assert.True(w.Offer(1, B(11)));

            Assert.True(w.TryDeliver(out byte[] p0));
            Assert.Equal(B(10), p0);
            Assert.True(w.TryDeliver(out byte[] p1));
            Assert.Equal(B(11), p1);
            Assert.False(w.TryDeliver(out _));
            Assert.Equal(2u, w.NextExpectedId);

            Assert.Equal(new uint[] { 0, 1 }, w.TakeAcks(8));
            Assert.Empty(w.PendingAcks);
        }

        [Fact]
        public void ReceiveWindow_BuffersOutOfOrderUntilGapFills()
        {
            var w = new OpenVpnReliableReceiveWindow();

            Assert.True(w.Offer(2, B(22)));          // arrives early
            Assert.True(w.Offer(1, B(11)));
            Assert.False(w.TryDeliver(out _));       // still waiting for 0

            Assert.True(w.Offer(0, B(0)));
            Assert.True(w.TryDeliver(out byte[] a)); Assert.Equal(B(0), a);
            Assert.True(w.TryDeliver(out byte[] b)); Assert.Equal(B(11), b);
            Assert.True(w.TryDeliver(out byte[] c)); Assert.Equal(B(22), c);
            Assert.False(w.TryDeliver(out _));
        }

        [Fact]
        public void ReceiveWindow_DuplicatesAreNotRedeliveredButAreReAcked()
        {
            var w = new OpenVpnReliableReceiveWindow();
            Assert.True(w.Offer(0, B(1)));
            Assert.True(w.TryDeliver(out _));
            w.TakeAcks(8);                           // clear the first ack

            Assert.False(w.Offer(0, B(1)));          // already delivered → duplicate
            Assert.False(w.TryDeliver(out _));       // not re-delivered
            Assert.Equal(new uint[] { 0 }, w.TakeAcks(8)); // but re-acked so the peer stops resending
        }

        [Fact]
        public void ReceiveWindow_DropsBeyondWindowWithoutAcking()
        {
            var w = new OpenVpnReliableReceiveWindow(new OpenVpnReliabilityOptions { WindowSize = 3 });
            // NextExpectedId = 0, window covers ids 0..2; id 3 is beyond it.
            Assert.False(w.Offer(3, B(9)));
            Assert.Empty(w.PendingAcks);             // not acked → peer keeps it and resends after 0..2 advance
        }

        [Fact]
        public void ReceiveWindow_TakeAcksRespectsMaxAndOrder()
        {
            var w = new OpenVpnReliableReceiveWindow();
            for (uint i = 0; i < 6; i++) Assert.True(w.Offer(i, B((byte)i)));

            Assert.Equal(new uint[] { 0, 1, 2, 3 }, w.TakeAcks(4)); // piggyback cap
            Assert.Equal(new uint[] { 4, 5 }, w.TakeAcks(8));       // remainder, still in order
            Assert.Empty(w.TakeAcks(8));
        }
    }
}
