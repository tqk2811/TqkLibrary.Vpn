using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using TqkLibrary.Vpn.IpStack.Tcp.Enums;

namespace TqkLibrary.Vpn.IpStack.Tcp
{
    /// <summary>
    /// An active-open TCP connection over the userspace stack. The peer is a real host on the internet (reached
    /// through the VPN gateway), so the send path implements reliability: every sequence-consuming segment is held
    /// in a retransmission queue, retransmitted on an RFC 6298 RTO (with RTT-estimated, exponentially backed-off
    /// timeout and a give-up cap), and the sender honours the peer's advertised receive window (sliding-window flow
    /// control + a zero-window persist probe). Received bytes are read via <see cref="ReadAsync"/>.
    /// </summary>
    /// <remarks>
    /// Still simplified on the receive side (out-of-order segments are dropped, not reassembled) and in the close
    /// FSM (no FINWAIT2/CLOSING/TIMEWAIT). Congestion control (cwnd/slow-start/fast-retransmit) is intentionally
    /// omitted — only flow control (the receiver window) is implemented.
    /// </remarks>
    public sealed class TcpConnection : IDisposable
    {
        const ushort Mss = 1360;
        const ushort ReceiveWindow = 65535;

        // RFC 6298 estimator constants.
        const double Alpha = 0.125;          // SRTT gain (1/8)
        const double Beta = 0.25;            // RTTVAR gain (1/4)
        const int K = 4;                     // RTTVAR multiplier
        const double ClockGranularityMs = 1; // G

        static readonly double MsPerTick = 1000.0 / Stopwatch.Frequency;

        readonly IPAddress _localIp;
        readonly IPAddress _remoteIp;
        readonly ushort _localPort;
        readonly ushort _remotePort;
        readonly Action<byte[]> _sendIp;
        readonly TcpRetransmitOptions _opts;
        readonly object _sync = new();
        readonly TaskCompletionSource<bool> _connected = new(TaskCreationOptions.RunContinuationsAsynchronously);

        // Receive buffer (separate lock so reads don't contend with the send path).
        readonly object _recvLock = new();
        readonly Queue<byte[]> _recvQueue = new();
        byte[]? _head;
        int _headPos;
        bool _recvCompleted;
        Exception? _recvError;
        TaskCompletionSource<bool>? _recvWaiter;

        uint _sndNxt;
        uint _sndUna;
        uint _rcvNxt;
        ushort _ipId = 1;
        TcpState _state = TcpState.Closed;

        // Send-side flow control (peer's advertised window + the RFC 793 window-update sequencing).
        uint _sndWnd;
        uint _sndWl1;
        uint _sndWl2;

        // Unsent application bytes waiting for window space (a queue of arrays + an offset into the head array).
        readonly Queue<byte[]> _sndChunks = new();
        int _sndChunkPos;
        int _sndBufferedBytes;

        // Deferred FIN: requested via CloseSend, emitted once the send buffer drains.
        bool _finRequested;
        bool _finSent;
        TcpState _finState;

        // Retransmission queue (oldest first) + RFC 6298 RTO estimator.
        readonly LinkedList<RetxUnit> _retx = new();
        int _retxAttempts;
        double _rtoMs;
        double _srtt = -1;
        double _rttvar;
        readonly Timer _rtoTimer;

        // Zero-window persist.
        readonly Timer _persistTimer;
        double _persistMs;
        bool _persistArmed;

        bool _terminal;

        /// <summary>Raised once when the connection faults (RST or retransmission give-up); lets the stack drop and dispose it.</summary>
        public event Action? Closed;

        /// <summary>Creates a connection from the local endpoint to the remote endpoint.</summary>
        public TcpConnection(
            IPAddress localIp, ushort localPort, IPAddress remoteIp, ushort remotePort, Action<byte[]> sendIp,
            TcpRetransmitOptions? options = null)
        {
            _localIp = localIp;
            _localPort = localPort;
            _remoteIp = remoteIp;
            _remotePort = remotePort;
            _sendIp = sendIp;
            _opts = options ?? TcpRetransmitOptions.Default;
            _rtoMs = _opts.InitialRto.TotalMilliseconds;
            _persistMs = _opts.PersistMin.TotalMilliseconds;
            _rtoTimer = new Timer(_ => OnRtoTimer(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            _persistTimer = new Timer(_ => OnPersistTimer(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        }

        /// <summary>This connection's local port.</summary>
        public ushort LocalPort => _localPort;

        /// <summary>Completes when the 3-way handshake finishes (or faults on RST).</summary>
        public Task Connected => _connected.Task;

        /// <summary>Sends the initial SYN.</summary>
        public void StartConnect()
        {
            lock (_sync)
            {
                byte[] r = new byte[4];
                using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(r);
                uint iss = ((uint)r[0] << 24) | ((uint)r[1] << 16) | ((uint)r[2] << 8) | r[3];
                _sndUna = iss;
                _sndNxt = iss;
                EmitSegment(iss, TcpFlags.Syn, ReadOnlySpan<byte>.Empty, mss: Mss);
                EnqueueRetx(iss, TcpFlags.Syn, Array.Empty<byte>(), seqLen: 1);
                _sndNxt = iss + 1;
                _state = TcpState.SynSent;
                ArmRtoTimer();
            }
        }

        /// <summary>Feeds one inbound TCP segment (the IP payload) into the state machine.</summary>
        public void OnSegment(ReadOnlyMemory<byte> segment)
        {
            lock (_sync) Handle(segment);
        }

        /// <summary>Queues application data to send (flushed within the peer's advertised window).</summary>
        public void Send(ReadOnlySpan<byte> data)
        {
            lock (_sync)
            {
                if (_terminal) return;
                if (data.Length > 0)
                {
                    _sndChunks.Enqueue(data.ToArray());
                    _sndBufferedBytes += data.Length;
                }
                TrySendData();
            }
        }

        /// <summary>Reads received bytes into <paramref name="buffer"/>; returns 0 at end of stream.</summary>
        public async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            while (true)
            {
                Task waiter;
                lock (_recvLock)
                {
                    if (_head == null && _recvQueue.Count > 0) { _head = _recvQueue.Dequeue(); _headPos = 0; }
                    if (_head != null)
                    {
                        int available = _head.Length - _headPos;
                        int n = Math.Min(available, count);
                        Buffer.BlockCopy(_head, _headPos, buffer, offset, n);
                        _headPos += n;
                        if (_headPos >= _head.Length) _head = null;
                        return n;
                    }
                    if (_recvError != null) throw _recvError;
                    if (_recvCompleted) return 0;
                    _recvWaiter = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    waiter = _recvWaiter.Task;
                }

                await Task.WhenAny(waiter, Task.Delay(Timeout.Infinite, cancellationToken)).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
            }
        }

        /// <summary>Requests a FIN to close our send side; the FIN is emitted once any buffered data has drained.</summary>
        public void CloseSend()
        {
            lock (_sync)
            {
                if (_terminal) return;
                if (_state == TcpState.Established) { _finRequested = true; _finState = TcpState.FinWait1; TrySendData(); }
                else if (_state == TcpState.CloseWait) { _finRequested = true; _finState = TcpState.LastAck; TrySendData(); }
            }
        }

        void Handle(ReadOnlyMemory<byte> segment)
        {
            ReadOnlySpan<byte> span = segment.Span;
            TcpFlags flags = TcpSegment.Flags(span);
            uint seq = TcpSegment.Sequence(span);
            uint ack = TcpSegment.Acknowledgment(span);
            ushort wnd = TcpSegment.Window(span);
            ReadOnlyMemory<byte> payload = TcpSegment.Payload(segment);
            int len = payload.Length;

            if ((flags & TcpFlags.Rst) != 0)
            {
                Fail("connection reset by peer");
                return;
            }

            switch (_state)
            {
                case TcpState.SynSent:
                    if ((flags & TcpFlags.Syn) != 0 && (flags & TcpFlags.Ack) != 0)
                    {
                        _rcvNxt = seq + 1;
                        ProcessAck(ack, seq, wnd);                 // acks our SYN, seeds the send window
                        EmitSegment(_sndNxt, TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
                        _state = TcpState.Established;
                        _connected.TrySetResult(true);
                        TrySendData();                             // flush anything queued before the handshake finished
                    }
                    break;

                case TcpState.Established:
                case TcpState.CloseWait:
                case TcpState.FinWait1:
                    if ((flags & TcpFlags.Ack) != 0) ProcessAck(ack, seq, wnd);

                    if (len > 0)
                    {
                        if (seq == _rcvNxt)
                        {
                            DeliverReceived(payload);
                            _rcvNxt += (uint)len;
                        }
                        EmitSegment(_sndNxt, TcpFlags.Ack, ReadOnlySpan<byte>.Empty); // cumulative ACK
                    }

                    if ((flags & TcpFlags.Fin) != 0 && seq + (uint)len == _rcvNxt)
                    {
                        _rcvNxt += 1;
                        EmitSegment(_sndNxt, TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
                        CompleteReceive(null);
                        _state = _state == TcpState.FinWait1 ? TcpState.LastAck : TcpState.CloseWait;
                    }
                    break;
            }
        }

        // ---- Send path: flow control + retransmission ------------------------------------------------------

        void TrySendData()
        {
            if (_terminal) return;
            bool canSend = _state == TcpState.Established || _state == TcpState.CloseWait;
            if (canSend)
            {
                while (_sndBufferedBytes > 0)
                {
                    int usable = (int)((_sndUna + _sndWnd) - _sndNxt); // signed window space left
                    if (usable <= 0) break;
                    int chunk = Math.Min(Math.Min((int)Mss, usable), _sndBufferedBytes);
                    EmitData(_sndNxt, DequeueUpTo(chunk));
                }

                if (_finRequested && !_finSent && _sndBufferedBytes == 0)
                    EmitFin();
            }

            if (canSend && !_finSent && _sndWnd == 0 && _sndBufferedBytes > 0) EnsurePersist();
            else StopPersist();

            ArmRtoTimer();
        }

        void ProcessAck(uint ack, uint segSeq, ushort segWnd)
        {
            if (SeqGreater(ack, _sndUna))
            {
                long now = Now();
                bool sampled = false;
                double sampleMs = 0;
                LinkedListNode<RetxUnit>? node = _retx.First;
                while (node != null && SeqGeq(ack, node.Value.Seq + (uint)node.Value.SeqLen))
                {
                    if (!node.Value.Retransmitted) { sampleMs = (now - node.Value.SentTicks) * MsPerTick; sampled = true; } // Karn: skip retransmitted
                    LinkedListNode<RetxUnit>? next = node.Next;
                    _retx.Remove(node);
                    node = next;
                }
                _sndUna = ack;
                _retxAttempts = 0;                  // forward progress resets the give-up counter
                if (sampled) UpdateRto(sampleMs);
            }

            // RFC 793 window update: accept only if this segment is newer (by seq, then by ack).
            if (SeqGreater(segSeq, _sndWl1) || (segSeq == _sndWl1 && !SeqGreater(_sndWl2, ack)))
            {
                if (_sndWnd == 0 && segWnd > 0) _persistMs = _opts.PersistMin.TotalMilliseconds; // window reopened
                _sndWnd = segWnd;
                _sndWl1 = segSeq;
                _sndWl2 = ack;
            }

            TrySendData();
        }

        void UpdateRto(double rttMs)
        {
            if (_srtt < 0) { _srtt = rttMs; _rttvar = rttMs / 2; }
            else
            {
                _rttvar = (1 - Beta) * _rttvar + Beta * Math.Abs(_srtt - rttMs);
                _srtt = (1 - Alpha) * _srtt + Alpha * rttMs;
            }
            double rto = _srtt + Math.Max(ClockGranularityMs, K * _rttvar);
            _rtoMs = Math.Min(Math.Max(rto, _opts.MinRto.TotalMilliseconds), _opts.MaxRto.TotalMilliseconds);
        }

        void EmitData(uint seq, byte[] payload)
        {
            EmitSegment(seq, TcpFlags.Psh | TcpFlags.Ack, payload);
            EnqueueRetx(seq, TcpFlags.Psh | TcpFlags.Ack, payload, seqLen: payload.Length);
            _sndNxt += (uint)payload.Length;
        }

        void EmitFin()
        {
            uint seq = _sndNxt;
            EmitSegment(seq, TcpFlags.Fin | TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
            EnqueueRetx(seq, TcpFlags.Fin | TcpFlags.Ack, Array.Empty<byte>(), seqLen: 1);
            _sndNxt += 1;
            _finSent = true;
            _state = _finState;
        }

        void EnqueueRetx(uint seq, TcpFlags flags, byte[] payload, int seqLen)
        {
            _retx.AddLast(new RetxUnit { Seq = seq, Flags = flags, Payload = payload, SeqLen = seqLen, SentTicks = Now() });
        }

        void EmitSegment(uint seq, TcpFlags flags, ReadOnlySpan<byte> payload, ushort mss = 0)
        {
            byte[] tcp = TcpSegment.Build(_localIp, _remoteIp, _localPort, _remotePort, seq, _rcvNxt, flags, ReceiveWindow, payload, mss);
            byte[] ip = Ipv4.Build(_localIp, _remoteIp, Ipv4.ProtocolTcp, tcp, _ipId++);
            _sendIp(ip);
        }

        byte[] DequeueUpTo(int max)
        {
            int want = Math.Min(max, _sndBufferedBytes);
            byte[] result = new byte[want];
            int copied = 0;
            while (copied < want)
            {
                byte[] head = _sndChunks.Peek();
                int take = Math.Min(head.Length - _sndChunkPos, want - copied);
                Buffer.BlockCopy(head, _sndChunkPos, result, copied, take);
                _sndChunkPos += take;
                copied += take;
                if (_sndChunkPos >= head.Length) { _sndChunks.Dequeue(); _sndChunkPos = 0; }
            }
            _sndBufferedBytes -= want;
            return result;
        }

        // ---- RTO timer (RFC 6298 §5) -----------------------------------------------------------------------

        void OnRtoTimer()
        {
            lock (_sync)
            {
                if (_terminal) return;
                LinkedListNode<RetxUnit>? node = _retx.First;
                if (node == null) return;

                long now = Now();
                long deadline = node.Value.SentTicks + (long)(_rtoMs / MsPerTick);
                if (now < deadline) { ArmRtoTimer(); return; } // woke early (timer coalescing) — re-arm

                if (++_retxAttempts > _opts.MaxRetransmits)
                {
                    Fail($"retransmission timeout (no ACK after {_opts.MaxRetransmits} retries)");
                    return;
                }

                RetxUnit u = node.Value;
                EmitSegment(u.Seq, u.Flags, u.Payload, (u.Flags & TcpFlags.Syn) != 0 ? Mss : (ushort)0);
                u.Retransmitted = true;
                u.SentTicks = now;
                _rtoMs = Math.Min(_rtoMs * 2, _opts.MaxRto.TotalMilliseconds); // exponential backoff (RFC 6298 §5.5)
                ArmRtoTimer();
            }
        }

        void ArmRtoTimer()
        {
            if (_terminal) return;
            LinkedListNode<RetxUnit>? node = _retx.First;
            if (node == null) { _rtoTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan); return; }
            long deadline = node.Value.SentTicks + (long)(_rtoMs / MsPerTick);
            double dueMs = Math.Max(0, (deadline - Now()) * MsPerTick);
            _rtoTimer.Change(TimeSpan.FromMilliseconds(dueMs), Timeout.InfiniteTimeSpan);
        }

        // ---- Zero-window persist (RFC 9293 §3.8.6.1) -------------------------------------------------------

        void EnsurePersist()
        {
            if (_persistArmed) return;
            _persistArmed = true;
            _persistTimer.Change(TimeSpan.FromMilliseconds(_persistMs), Timeout.InfiniteTimeSpan);
        }

        void StopPersist()
        {
            if (!_persistArmed) return;
            _persistArmed = false;
            _persistTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        }

        void OnPersistTimer()
        {
            lock (_sync)
            {
                if (_terminal) return;
                bool canSend = _state == TcpState.Established || _state == TcpState.CloseWait;
                if (!canSend || _sndWnd != 0 || _sndBufferedBytes == 0) { StopPersist(); return; }

                // Send one probe byte only when nothing is already in flight, so at most one byte sits beyond the
                // zero window; the RTO timer retransmits it until acked, after which the next probe goes out.
                if (_retx.Count == 0)
                {
                    EmitData(_sndNxt, DequeueUpTo(1));
                    ArmRtoTimer();
                }

                _persistMs = Math.Min(_persistMs * 2, _opts.PersistMax.TotalMilliseconds);
                _persistTimer.Change(TimeSpan.FromMilliseconds(_persistMs), Timeout.InfiniteTimeSpan);
            }
        }

        // ---- Receive delivery ------------------------------------------------------------------------------

        void DeliverReceived(ReadOnlyMemory<byte> payload)
        {
            byte[] copy = payload.ToArray();
            lock (_recvLock)
            {
                _recvQueue.Enqueue(copy);
                Signal();
            }
        }

        void CompleteReceive(Exception? error)
        {
            lock (_recvLock)
            {
                _recvCompleted = true;
                _recvError = error;
                Signal();
            }
        }

        void Signal()
        {
            TaskCompletionSource<bool>? waiter = _recvWaiter;
            _recvWaiter = null;
            waiter?.TrySetResult(true);
        }

        void Fail(string message)
        {
            if (_terminal) return;
            _terminal = true;
            _rtoTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            _persistTimer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            _persistArmed = false;
            _state = TcpState.Closed;
            var error = new IOException(message);
            _connected.TrySetException(error);
            CompleteReceive(error);

            Action? handler = Closed;
            Closed = null;
            handler?.Invoke();
        }

        /// <summary>Stops the retransmission/persist timers. Idempotent; also invoked when the connection faults.</summary>
        public void Dispose()
        {
            _rtoTimer.Dispose();
            _persistTimer.Dispose();
        }

        static bool SeqGreater(uint a, uint b) => (int)(a - b) > 0;
        static bool SeqGeq(uint a, uint b) => (int)(a - b) >= 0;
        static long Now() => Stopwatch.GetTimestamp();

        /// <summary>One unacked, sequence-consuming segment held for possible retransmission.</summary>
        sealed class RetxUnit
        {
            public uint Seq;
            public TcpFlags Flags;
            public byte[] Payload = Array.Empty<byte>();
            public int SeqLen;       // sequence space consumed: payload length, or 1 for a lone SYN/FIN
            public long SentTicks;
            public bool Retransmitted;
        }
    }
}
