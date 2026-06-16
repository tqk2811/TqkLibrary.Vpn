namespace TqkLibrary.VpnClient.OpenVpn
{
    /// <summary>
    /// The send half of the OpenVPN control-channel reliability layer: assigns each outgoing control payload a
    /// monotonic 32-bit packet-id (from 0), keeps it in a bounded in-flight window until the peer acknowledges it, and
    /// surfaces packets that are due for (re)transmission. Timing is caller-driven — every method that cares about time
    /// takes a millisecond clock value — so the driver pumps it from a timer while tests drive it deterministically.
    /// Not thread-safe; the owning control channel serialises access.
    /// </summary>
    public sealed class OpenVpnReliableSendWindow
    {
        sealed class Entry
        {
            public uint Id;
            public byte[] Payload = Array.Empty<byte>();
            public long? LastSentMs;   // null until first transmitted
            public int Transmits;      // total times sent (1 after the initial send)
        }

        readonly OpenVpnReliabilityOptions _options;
        readonly List<Entry> _pending = new();
        uint _nextId;

        /// <summary>Creates the window with the given retransmit/window policy (defaults when null).</summary>
        public OpenVpnReliableSendWindow(OpenVpnReliabilityOptions? options = null)
        {
            _options = options ?? new OpenVpnReliabilityOptions();
        }

        /// <summary>The packet-id the next <see cref="Queue"/> will assign.</summary>
        public uint NextPacketId => _nextId;

        /// <summary>Control packets queued but not yet acknowledged.</summary>
        public int InFlight => _pending.Count;

        /// <summary>True while the in-flight window has room for another packet.</summary>
        public bool CanQueue => _pending.Count < _options.WindowSize;

        /// <summary>
        /// Assigns the next packet-id to <paramref name="payload"/> and stores it for reliable delivery (not yet sent —
        /// the next <see cref="CollectDue"/> emits it). Throws if the window is full (<see cref="CanQueue"/> is false).
        /// </summary>
        public uint Queue(byte[] payload)
        {
            if (!CanQueue) throw new InvalidOperationException("OpenVPN reliable send window is full.");
            uint id = _nextId++;
            _pending.Add(new Entry { Id = id, Payload = payload });
            return id;
        }

        /// <summary>
        /// Returns the packets to put on the wire now — those never sent, plus those whose retransmit interval has
        /// elapsed — and marks them transmitted at <paramref name="nowMs"/>. Packets that have exhausted their resend
        /// budget are not resent (see <see cref="IsExhausted"/>).
        /// </summary>
        public IReadOnlyList<(uint Id, byte[] Payload)> CollectDue(long nowMs)
        {
            var due = new List<(uint, byte[])>();
            foreach (Entry e in _pending)
            {
                if (e.LastSentMs is null)
                {
                    e.LastSentMs = nowMs;
                    e.Transmits = 1;
                    due.Add((e.Id, e.Payload));
                    continue;
                }
                long gapMs = (long)_options.IntervalFor(e.Transmits - 1).TotalMilliseconds;
                if (nowMs - e.LastSentMs.Value < gapMs) continue;
                if (_options.MaxRetransmits > 0 && e.Transmits >= 1 + _options.MaxRetransmits) continue; // dead — see IsExhausted
                e.LastSentMs = nowMs;
                e.Transmits++;
                due.Add((e.Id, e.Payload));
            }
            return due;
        }

        /// <summary>
        /// True once some in-flight packet has used its whole resend budget (initial send + <c>MaxRetransmits</c>) and
        /// the next interval has still elapsed without an ack — the peer is dead. Always false when MaxRetransmits is 0.
        /// </summary>
        public bool IsExhausted(long nowMs)
        {
            if (_options.MaxRetransmits <= 0) return false;
            foreach (Entry e in _pending)
            {
                if (e.LastSentMs is null) continue;
                if (e.Transmits >= 1 + _options.MaxRetransmits
                    && nowMs - e.LastSentMs.Value >= (long)_options.IntervalFor(e.Transmits - 1).TotalMilliseconds)
                    return true;
            }
            return false;
        }

        /// <summary>Clears one acknowledged packet from the window. Returns true if it was in flight.</summary>
        public bool Acknowledge(uint id) => _pending.RemoveAll(e => e.Id == id) > 0;

        /// <summary>Clears every acknowledged packet-id from the window (the ack array of an inbound packet).</summary>
        public void Acknowledge(IEnumerable<uint> ids)
        {
            foreach (uint id in ids) Acknowledge(id);
        }
    }
}
