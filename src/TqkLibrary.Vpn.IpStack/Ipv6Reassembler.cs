using System.Diagnostics;

namespace TqkLibrary.Vpn.IpStack
{
    /// <summary>
    /// Reassembles inbound fragmented IPv6 datagrams carried in the Fragment extension header (RFC 8200 §4.5). Whole
    /// (non-fragmented) packets pass through unchanged; fragments are buffered per (source, destination, identification)
    /// until the datagram is complete or a timeout elapses, then emitted as a single packet with the Fragment header
    /// unlinked. Incomplete datagrams are discarded after <see cref="Ipv6ReassemblyOptions.Timeout"/>, and the oldest is
    /// evicted once <see cref="Ipv6ReassemblyOptions.MaxConcurrent"/> is exceeded (DoS protection). Thread-safe.
    /// </summary>
    public sealed class Ipv6Reassembler
    {
        readonly Ipv6ReassemblyOptions _options;
        readonly long _timeoutTicks;
        readonly Dictionary<Key, Partial> _pending = new Dictionary<Key, Partial>();
        readonly object _gate = new object();

        /// <summary>Creates a reassembler with default options.</summary>
        public Ipv6Reassembler() : this(Ipv6ReassemblyOptions.Default) { }

        /// <summary>Creates a reassembler with the given options.</summary>
        public Ipv6Reassembler(Ipv6ReassemblyOptions options)
        {
            _options = options ?? Ipv6ReassemblyOptions.Default;
            _timeoutTicks = (long)(_options.Timeout.TotalSeconds * Stopwatch.Frequency);
        }

        /// <summary>Number of in-progress (incomplete) datagrams currently buffered.</summary>
        public int PendingCount { get { lock (_gate) return _pending.Count; } }

        /// <summary>
        /// Offers an inbound IPv6 packet. A non-fragmented packet is returned unchanged. A fragment is buffered and
        /// <c>null</c> is returned until its datagram is complete, at which point the fully reassembled packet is
        /// returned. Malformed or over-limit fragments are dropped (<c>null</c>).
        /// </summary>
        public ReadOnlyMemory<byte>? Offer(ReadOnlyMemory<byte> ipPacket)
        {
            ReadOnlySpan<byte> span = ipPacket.Span;
            if (span.Length < Ipv6.HeaderLength) return ipPacket; // too short to be a fragment; caller guards reject it

            if (!Ipv6.TryGetFragment(span, out int unfragmentableLength, out int nextHeaderFieldOffset, out byte fragmentNextHeader, out int fragmentOffset, out bool moreFragments, out uint identification))
                return ipPacket; // whole datagram, not a fragment (or malformed chain)

            int payloadStart = unfragmentableLength + Ipv6.FragmentHeaderLength;
            int fragmentLength = span.Length - payloadStart;
            if (fragmentLength < 0) return null; // malformed
            int start = fragmentOffset;
            int end = fragmentOffset + fragmentLength;
            if (end > _options.MaxDatagramSize) return null; // would exceed the datagram cap

            long now = Stopwatch.GetTimestamp();
            Key key = Key.From(span, identification);

            lock (_gate)
            {
                Expire(now);

                if (!_pending.TryGetValue(key, out Partial? part))
                {
                    if (_pending.Count >= _options.MaxConcurrent) EvictOldest();
                    part = new Partial(now + _timeoutTicks, now);
                    _pending[key] = part;
                }

                part.CaptureHeader(span, unfragmentableLength, nextHeaderFieldOffset, fragmentNextHeader);
                part.Add(start, end, span.Slice(payloadStart, fragmentLength));
                if (!moreFragments) part.TotalLength = end;

                if (!part.IsComplete) return null;

                _pending.Remove(key);
                return part.Rebuild();
            }
        }

        void Expire(long now)
        {
            if (_pending.Count == 0) return;
            List<Key>? dead = null;
            foreach (KeyValuePair<Key, Partial> kv in _pending)
                if (kv.Value.Deadline <= now) (dead ??= new List<Key>()).Add(kv.Key);
            if (dead != null)
                foreach (Key k in dead) _pending.Remove(k);
        }

        void EvictOldest()
        {
            Key oldest = default;
            long min = long.MaxValue;
            bool found = false;
            foreach (KeyValuePair<Key, Partial> kv in _pending)
                if (kv.Value.FirstSeenTicks < min) { min = kv.Value.FirstSeenTicks; oldest = kv.Key; found = true; }
            if (found) _pending.Remove(oldest);
        }

        /// <summary>Identifies a datagram being reassembled: (source, destination, identification).</summary>
        readonly struct Key : IEquatable<Key>
        {
            readonly ulong _srcHi, _srcLo, _dstHi, _dstLo;
            readonly uint _identification;

            Key(ulong srcHi, ulong srcLo, ulong dstHi, ulong dstLo, uint identification)
            {
                _srcHi = srcHi; _srcLo = srcLo; _dstHi = dstHi; _dstLo = dstLo; _identification = identification;
            }

            public static Key From(ReadOnlySpan<byte> span, uint identification)
                => new Key(ReadU64(span, 8), ReadU64(span, 16), ReadU64(span, 24), ReadU64(span, 32), identification);

            static ulong ReadU64(ReadOnlySpan<byte> b, int o)
            {
                ulong v = 0;
                for (int i = 0; i < 8; i++) v = (v << 8) | b[o + i];
                return v;
            }

            public bool Equals(Key other) =>
                _srcHi == other._srcHi && _srcLo == other._srcLo &&
                _dstHi == other._dstHi && _dstLo == other._dstLo &&
                _identification == other._identification;

            public override bool Equals(object? obj) => obj is Key other && Equals(other);

            public override int GetHashCode()
            {
                unchecked
                {
                    int hash = (int)(_srcHi ^ _srcLo);
                    hash = hash * 397 ^ (int)(_dstHi ^ _dstLo);
                    hash = hash * 397 ^ (int)_identification;
                    return hash;
                }
            }
        }

        /// <summary>One datagram under reassembly: the unfragmentable-header template plus the coalesced fragmentable bytes.</summary>
        sealed class Partial
        {
            readonly List<(int Start, int End)> _intervals = new List<(int, int)>();
            byte[] _header = Array.Empty<byte>();
            int _nextHeaderFieldOffset;
            byte _fragmentNextHeader;
            bool _headerCaptured;

            public Partial(long deadline, long firstSeenTicks)
            {
                Deadline = deadline;
                FirstSeenTicks = firstSeenTicks;
            }

            /// <summary>Monotonic tick after which this incomplete datagram is discarded.</summary>
            public long Deadline { get; }

            /// <summary>Monotonic tick of the first fragment seen — used to evict the oldest datagram when over capacity.</summary>
            public long FirstSeenTicks { get; }

            /// <summary>Length of the fragmentable payload once the last fragment (M cleared) has been seen, else -1.</summary>
            public int TotalLength { get; set; } = -1;

            /// <summary>Staging buffer holding received fragmentable bytes at their payload offsets; grows on demand.</summary>
            byte[] Buffer { get; set; } = Array.Empty<byte>();

            /// <summary>The datagram is whole when the last fragment is in and the received ranges cover [0, TotalLength).</summary>
            public bool IsComplete =>
                TotalLength >= 0 && _intervals.Count == 1 && _intervals[0].Start == 0 && _intervals[0].End == TotalLength;

            /// <summary>Captures the unfragmentable header (identical across fragments) the first time any fragment arrives.</summary>
            public void CaptureHeader(ReadOnlySpan<byte> span, int unfragmentableLength, int nextHeaderFieldOffset, byte fragmentNextHeader)
            {
                if (_headerCaptured) return;
                _header = span.Slice(0, unfragmentableLength).ToArray();
                _nextHeaderFieldOffset = nextHeaderFieldOffset;
                _fragmentNextHeader = fragmentNextHeader;
                _headerCaptured = true;
            }

            public void Add(int start, int end, ReadOnlySpan<byte> data)
            {
                if (Buffer.Length < end)
                {
                    byte[] grown = new byte[end];
                    Array.Copy(Buffer, grown, Buffer.Length);
                    Buffer = grown;
                }
                data.CopyTo(Buffer.AsSpan(start, end - start));
                Coalesce(start, end);
            }

            /// <summary>Reassembles the full IPv6 packet: unfragmentable header (Fragment unlinked) + the fragmentable payload.</summary>
            public ReadOnlyMemory<byte> Rebuild()
            {
                int total = _header.Length + TotalLength;
                byte[] packet = new byte[total];
                Array.Copy(_header, packet, _header.Length);
                packet[_nextHeaderFieldOffset] = _fragmentNextHeader; // unlink the Fragment header
                int payloadLength = total - Ipv6.HeaderLength;
                packet[4] = (byte)(payloadLength >> 8);
                packet[5] = (byte)payloadLength;
                Array.Copy(Buffer, 0, packet, _header.Length, TotalLength);
                return packet;
            }

            void Coalesce(int start, int end)
            {
                _intervals.Add((start, end));
                _intervals.Sort((a, b) => a.Start.CompareTo(b.Start));
                int write = 0;
                for (int read = 1; read < _intervals.Count; read++)
                {
                    (int Start, int End) current = _intervals[write];
                    (int Start, int End) next = _intervals[read];
                    if (next.Start <= current.End) // overlapping or touching → merge
                        _intervals[write] = (current.Start, Math.Max(current.End, next.End));
                    else
                        _intervals[++write] = next;
                }
                _intervals.RemoveRange(write + 1, _intervals.Count - (write + 1));
            }
        }
    }
}
