using TqkLibrary.Vpn.L2tp.Models;

namespace TqkLibrary.Vpn.L2tp
{
    /// <summary>
    /// The L2TP reliable control channel (RFC 2661 §5.8): assigns Ns to outgoing control messages, tracks Nr to
    /// acknowledge the peer, retransmits unacknowledged messages, and delivers in-order messages to the caller.
    /// Acks are cumulative (a received Nr clears every queued message below it); ZLB messages only carry acks.
    /// </summary>
    public sealed class L2tpControlChannel : IDisposable
    {
        readonly Func<ReadOnlyMemory<byte>, Task> _send;
        readonly object _sync = new();
        readonly LinkedList<Outstanding> _unacked = new();
        readonly System.Threading.Timer _retransmitTimer;
        readonly TimeSpan _retransmitInterval;

        ushort _ns;
        ushort _nr;

        /// <summary>Creates the channel over a datagram sink, with an optional retransmit interval.</summary>
        public L2tpControlChannel(Func<ReadOnlyMemory<byte>, Task> send, TimeSpan? retransmitInterval = null)
        {
            _send = send;
            _retransmitInterval = retransmitInterval ?? TimeSpan.FromSeconds(1);
            _retransmitTimer = new System.Threading.Timer(_ => Retransmit(), null, _retransmitInterval, _retransmitInterval);
        }

        /// <summary>The peer's tunnel id, learned from its Assigned Tunnel ID AVP (used to address outgoing messages).</summary>
        public ushort PeerTunnelId { get; set; }

        /// <summary>Raised for each in-order control message carrying AVPs (ZLB acks are consumed internally).</summary>
        public event Action<L2tpControlMessage>? ControlReceived;

        /// <summary>Sends a control message reliably: assigns Ns/Nr, queues it for retransmit, and transmits it.</summary>
        public Task SendAsync(L2tpControlMessage message)
        {
            byte[] wire;
            lock (_sync)
            {
                message.TunnelId = PeerTunnelId;
                message.Ns = _ns;
                message.Nr = _nr;
                wire = L2tpCodec.EncodeControl(message);
                _unacked.AddLast(new Outstanding(_ns, wire));
                _ns++;
            }
            return _send(wire);
        }

        /// <summary>Feeds one received L2TP datagram (control or data ignored) into the reliability state machine.</summary>
        public void OnDatagram(ReadOnlyMemory<byte> datagram)
        {
            if (!L2tpCodec.IsControl(datagram.Span)) return;
            L2tpControlMessage message = L2tpCodec.DecodeControl(datagram.Span);

            bool deliver = false;
            lock (_sync)
            {
                // Cumulative ack: drop every queued message the peer has now acknowledged.
                while (_unacked.First is { } node && SeqLess(node.Value.Ns, message.Nr))
                    _unacked.RemoveFirst();

                if (message.IsZeroLengthBody)
                    return; // pure ack — nothing to deliver or re-ack

                if (message.Ns == _nr)
                {
                    _nr++;
                    deliver = true;
                }
                else if (SeqLess(message.Ns, _nr))
                {
                    // Duplicate the peer retransmitted because it missed our ack — re-acknowledge.
                    _ = SendAckAsync();
                }
            }

            if (deliver)
            {
                ControlReceived?.Invoke(message);
                _ = SendAckAsync(); // a standalone ack; harmless if the caller also sends a reply that re-acks
            }
        }

        /// <summary>Sends a ZLB acknowledgement carrying the current Nr (no Ns consumption, not retransmitted).</summary>
        public Task SendAckAsync()
        {
            byte[] wire;
            lock (_sync)
            {
                var ack = new L2tpControlMessage { IsZeroLengthBody = true, TunnelId = PeerTunnelId, Ns = _ns, Nr = _nr };
                wire = L2tpCodec.EncodeControl(ack);
            }
            return _send(wire);
        }

        void Retransmit()
        {
            byte[]? wire = null;
            lock (_sync)
            {
                if (_unacked.First is { } node) wire = node.Value.Wire;
            }
            if (wire != null) _ = _send(wire);
        }

        static bool SeqLess(ushort a, ushort b) => (short)(a - b) < 0;

        /// <inheritdoc/>
        public void Dispose() => _retransmitTimer.Dispose();

        readonly struct Outstanding
        {
            public Outstanding(ushort ns, byte[] wire) { Ns = ns; Wire = wire; }
            public ushort Ns { get; }
            public byte[] Wire { get; }
        }
    }
}
