namespace TqkLibrary.VpnClient.OpenVpn
{
    /// <summary>
    /// The receive half of the OpenVPN control-channel reliability layer: deduplicates inbound control packet-ids,
    /// buffers out-of-order ones within a bounded window, releases payloads to the TLS layer in strict packet-id order
    /// (from 0), and tracks which ids still need acknowledging. Every received id (even a duplicate already delivered)
    /// is re-queued for ack, because the peer resends until it sees the ack. Not thread-safe.
    /// </summary>
    public sealed class OpenVpnReliableReceiveWindow
    {
        readonly int _windowSize;
        readonly SortedDictionary<uint, byte[]> _buffer = new(); // received, not yet delivered (id >= NextExpectedId)
        readonly List<uint> _pendingAcks = new();
        uint _nextDeliverId;

        /// <summary>Creates the window with the given policy (only <see cref="OpenVpnReliabilityOptions.WindowSize"/> is used).</summary>
        public OpenVpnReliableReceiveWindow(OpenVpnReliabilityOptions? options = null)
        {
            _windowSize = (options ?? new OpenVpnReliabilityOptions()).WindowSize;
        }

        /// <summary>The packet-id the next in-order delivery expects.</summary>
        public uint NextExpectedId => _nextDeliverId;

        /// <summary>Packet-ids received but not yet handed out by <see cref="TakeAcks"/>.</summary>
        public IReadOnlyList<uint> PendingAcks => _pendingAcks;

        /// <summary>
        /// Offers a received control packet. Returns true if it is new and now buffered for in-order delivery; false if
        /// it is a duplicate (already delivered or already buffered) or falls beyond the receive window. New and
        /// duplicate ids are queued for acknowledgement; out-of-window ids are dropped silently (the peer will resend).
        /// </summary>
        public bool Offer(uint id, byte[] payload)
        {
            if (id < _nextDeliverId) { QueueAck(id); return false; }                 // already delivered → dup, re-ack
            if ((long)id >= (long)_nextDeliverId + _windowSize) return false;        // beyond window → drop, no ack
            if (_buffer.ContainsKey(id)) { QueueAck(id); return false; }             // already buffered → dup, re-ack
            _buffer[id] = payload;
            QueueAck(id);
            return true;
        }

        /// <summary>
        /// Releases the next in-order payload, advancing the expected id. Returns false when the next expected id has
        /// not arrived yet (a gap). Call in a loop to drain everything currently contiguous.
        /// </summary>
        public bool TryDeliver(out byte[] payload)
        {
            if (_buffer.TryGetValue(_nextDeliverId, out byte[]? buffered))
            {
                _buffer.Remove(_nextDeliverId);
                _nextDeliverId++;
                payload = buffered;
                return true;
            }
            payload = Array.Empty<byte>();
            return false;
        }

        /// <summary>
        /// Removes and returns up to <paramref name="max"/> packet-ids that need acknowledging (oldest first) — feed
        /// these into a P_ACK_V1 (up to 8) or piggyback them on an outgoing P_CONTROL (up to 4).
        /// </summary>
        public IReadOnlyList<uint> TakeAcks(int max)
        {
            int n = Math.Min(Math.Max(0, max), _pendingAcks.Count);
            if (n == 0) return Array.Empty<uint>();
            List<uint> taken = _pendingAcks.GetRange(0, n);
            _pendingAcks.RemoveRange(0, n);
            return taken;
        }

        void QueueAck(uint id)
        {
            if (!_pendingAcks.Contains(id)) _pendingAcks.Add(id);
        }
    }
}
