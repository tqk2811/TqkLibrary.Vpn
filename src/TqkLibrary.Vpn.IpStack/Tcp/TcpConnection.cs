using System.IO;
using System.Net;
using System.Security.Cryptography;
using TqkLibrary.Vpn.IpStack.Tcp.Enums;

namespace TqkLibrary.Vpn.IpStack.Tcp
{
    /// <summary>
    /// A minimal active-open TCP connection over the userspace stack. The SSTP/L2TP tunnel underneath is a
    /// reliable, in-order byte stream, so this implementation omits retransmission/SACK and handles the
    /// handshake, in-order data, ACKs and FIN. Received bytes are read via <see cref="ReadAsync"/>.
    /// </summary>
    public sealed class TcpConnection
    {
        const ushort Mss = 1360;
        const ushort ReceiveWindow = 65535;

        readonly IPAddress _localIp;
        readonly IPAddress _remoteIp;
        readonly ushort _localPort;
        readonly ushort _remotePort;
        readonly Action<byte[]> _sendIp;
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

        /// <summary>Creates a connection from the local endpoint to the remote endpoint.</summary>
        public TcpConnection(IPAddress localIp, ushort localPort, IPAddress remoteIp, ushort remotePort, Action<byte[]> sendIp)
        {
            _localIp = localIp;
            _localPort = localPort;
            _remoteIp = remoteIp;
            _remotePort = remotePort;
            _sendIp = sendIp;
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
                SendSegment(TcpFlags.Syn, ReadOnlySpan<byte>.Empty, mss: Mss); // seq = iss
                _sndNxt = iss + 1;
                _state = TcpState.SynSent;
            }
        }

        /// <summary>Feeds one inbound TCP segment (the IP payload) into the state machine.</summary>
        public void OnSegment(ReadOnlyMemory<byte> segment)
        {
            lock (_sync) Handle(segment);
        }

        /// <summary>Queues application data to send.</summary>
        public void Send(ReadOnlySpan<byte> data)
        {
            lock (_sync)
            {
                int offset = 0;
                while (offset < data.Length)
                {
                    int chunk = Math.Min(Mss, data.Length - offset);
                    SendSegment(TcpFlags.Psh | TcpFlags.Ack, data.Slice(offset, chunk));
                    _sndNxt += (uint)chunk;
                    offset += chunk;
                }
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

        /// <summary>Sends a FIN to start closing our send side.</summary>
        public void CloseSend()
        {
            lock (_sync)
            {
                if (_state == TcpState.Established)
                {
                    SendSegment(TcpFlags.Fin | TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
                    _sndNxt += 1;
                    _state = TcpState.FinWait1;
                }
                else if (_state == TcpState.CloseWait)
                {
                    SendSegment(TcpFlags.Fin | TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
                    _sndNxt += 1;
                    _state = TcpState.LastAck;
                }
            }
        }

        void Handle(ReadOnlyMemory<byte> segment)
        {
            ReadOnlySpan<byte> span = segment.Span;
            TcpFlags flags = TcpSegment.Flags(span);
            uint seq = TcpSegment.Sequence(span);
            uint ack = TcpSegment.Acknowledgment(span);
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
                        _sndUna = ack;
                        SendSegment(TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
                        _state = TcpState.Established;
                        _connected.TrySetResult(true);
                    }
                    break;

                case TcpState.Established:
                case TcpState.CloseWait:
                case TcpState.FinWait1:
                    if ((flags & TcpFlags.Ack) != 0 && SeqGreater(ack, _sndUna)) _sndUna = ack;

                    if (len > 0)
                    {
                        if (seq == _rcvNxt)
                        {
                            DeliverReceived(payload);
                            _rcvNxt += (uint)len;
                        }
                        SendSegment(TcpFlags.Ack, ReadOnlySpan<byte>.Empty); // cumulative ACK
                    }

                    if ((flags & TcpFlags.Fin) != 0 && seq + (uint)len == _rcvNxt)
                    {
                        _rcvNxt += 1;
                        SendSegment(TcpFlags.Ack, ReadOnlySpan<byte>.Empty);
                        CompleteReceive(null);
                        _state = _state == TcpState.FinWait1 ? TcpState.LastAck : TcpState.CloseWait;
                    }
                    break;
            }
        }

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

        void SendSegment(TcpFlags flags, ReadOnlySpan<byte> payload, ushort mss = 0)
        {
            byte[] tcp = TcpSegment.Build(_localIp, _remoteIp, _localPort, _remotePort, _sndNxt, _rcvNxt, flags, ReceiveWindow, payload, mss);
            byte[] ip = Ipv4.Build(_localIp, _remoteIp, Ipv4.ProtocolTcp, tcp, _ipId++);
            _sendIp(ip);
        }

        void Fail(string message)
        {
            _connected.TrySetException(new IOException(message));
            CompleteReceive(new IOException(message));
        }

        static bool SeqGreater(uint a, uint b) => (int)(a - b) > 0;
    }
}
