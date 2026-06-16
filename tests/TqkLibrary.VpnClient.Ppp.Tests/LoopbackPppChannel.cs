using TqkLibrary.VpnClient.Ppp.Interfaces;

namespace TqkLibrary.VpnClient.Ppp.Tests
{
    /// <summary>In-memory PPP frame channel: frames sent on one end are queued for delivery on the other.</summary>
    internal sealed class LoopbackPppChannel : IPppFrameChannel
    {
        readonly Queue<byte[]> _inbox = new();
        LoopbackPppChannel _peer = null!;

        public event Action<ReadOnlyMemory<byte>>? FrameReceived;

        public static (LoopbackPppChannel client, LoopbackPppChannel server) CreatePair()
        {
            var a = new LoopbackPppChannel();
            var b = new LoopbackPppChannel();
            a._peer = b;
            b._peer = a;
            return (a, b);
        }

        public ValueTask SendAsync(ReadOnlyMemory<byte> frame, CancellationToken cancellationToken = default)
        {
            _peer._inbox.Enqueue(frame.ToArray());
            return default;
        }

        /// <summary>Delivers one queued inbound frame; returns false if none pending.</summary>
        public bool Deliver()
        {
            if (_inbox.Count == 0) return false;
            byte[] frame = _inbox.Dequeue();
            FrameReceived?.Invoke(frame);
            return true;
        }

        /// <summary>Pumps both ends until quiescent (or a safety cap is hit).</summary>
        public static void Pump(LoopbackPppChannel a, LoopbackPppChannel b)
        {
            int guard = 0;
            while ((a.Deliver() | b.Deliver()) && guard++ < 1000)
            {
            }
        }
    }
}
