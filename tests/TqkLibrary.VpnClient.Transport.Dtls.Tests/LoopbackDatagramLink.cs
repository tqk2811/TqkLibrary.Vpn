using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Transport.Dtls.Tests
{
    /// <summary>
    /// An in-memory, connected datagram pipe with two ends (client/server) whose <see cref="IDatagramTransport.SendAsync"/>
    /// delivers one datagram to the peer's inbound queue — preserving boundaries like UDP. A per-end
    /// <see cref="LoopbackDatagramLink.End.NetworkConditions"/> hook can <b>drop</b> or <b>delay/reorder</b> the datagram
    /// the end emits, so a test can exercise the DTLS retransmit/reorder paths over an otherwise lossless loopback. This
    /// is throwaway test scaffolding standing in for a real UDP socket.
    /// </summary>
    sealed class LoopbackDatagramLink
    {
        public LoopbackDatagramLink()
        {
            var c2s = Channel.CreateUnbounded<byte[]>();
            var s2c = Channel.CreateUnbounded<byte[]>();
            Client = new End(inbound: s2c, peerInbound: c2s);
            Server = new End(inbound: c2s, peerInbound: s2c);
        }

        /// <summary>The client end (the <see cref="DtlsDatagramTransport"/>'s inner pipe).</summary>
        public End Client { get; }

        /// <summary>The server end (the BouncyCastle DTLS server's pipe).</summary>
        public End Server { get; }

        /// <summary>
        /// Per-datagram network condition applied to what an end sends. Returns the (possibly empty) sequence of
        /// datagrams to actually deliver to the peer: an empty result drops the datagram; multiple results can reorder
        /// (e.g. by buffering one and flushing it after a later one). It is called under the end's send lock so it is
        /// invoked once per send in order.
        /// </summary>
        public delegate IEnumerable<byte[]> NetworkCondition(byte[] datagram);

        /// <summary>One end of the datagram pipe: reads its inbound channel, applies its condition, writes to the peer's.</summary>
        public sealed class End : IDatagramTransport
        {
            readonly Channel<byte[]> _inbound;
            readonly Channel<byte[]> _peerInbound;
            readonly object _sendLock = new();

            internal End(Channel<byte[]> inbound, Channel<byte[]> peerInbound)
            {
                _inbound = inbound;
                _peerInbound = peerInbound;
            }

            /// <summary>Optional drop/reorder hook applied to each datagram this end sends; null = lossless ordered.</summary>
            public NetworkCondition? NetworkConditions { get; set; }

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

            public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
            {
                byte[] copy = datagram.ToArray();
                lock (_sendLock)
                {
                    NetworkCondition? condition = NetworkConditions;
                    if (condition is null)
                    {
                        _peerInbound.Writer.TryWrite(copy);
                    }
                    else
                    {
                        foreach (byte[] outgoing in condition(copy))
                            _peerInbound.Writer.TryWrite(outgoing);
                    }
                }
                return default;
            }

            public async ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                byte[] datagram;
                try { datagram = await _inbound.Reader.ReadAsync(cancellationToken).ConfigureAwait(false); }
                catch (ChannelClosedException) { return 0; }
                int n = Math.Min(buffer.Length, datagram.Length);
                datagram.AsMemory(0, n).CopyTo(buffer);
                return n;
            }

            public ValueTask DisposeAsync()
            {
                _peerInbound.Writer.TryComplete(); // closing one end surfaces as EOF on the peer's reads
                return default;
            }
        }
    }
}
