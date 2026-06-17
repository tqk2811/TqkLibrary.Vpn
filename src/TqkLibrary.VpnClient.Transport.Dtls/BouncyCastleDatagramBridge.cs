using System.Collections.Concurrent;
using Org.BouncyCastle.Tls;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;

namespace TqkLibrary.VpnClient.Transport.Dtls
{
    /// <summary>
    /// Adapts our async <see cref="IDatagramTransport"/> (the outer UDP pipe) to BouncyCastle's <b>synchronous</b>
    /// <see cref="Org.BouncyCastle.Tls.DatagramTransport"/>, which the DTLS record layer drives directly.
    /// <para>
    /// BouncyCastle's record layer is blocking: it calls <see cref="Send"/> inline and <see cref="Receive(byte[],int,int,int)"/>
    /// with a <c>waitMillis</c> timeout (returning <c>-1</c> on timeout so its retransmit logic can fire). The inner pipe is
    /// async, so a background receive loop pulls datagrams off it and parks them in a bounded queue that <see cref="Receive(byte[],int,int,int)"/>
    /// blocks on. Sends run the inner <see cref="IDatagramTransport.SendAsync"/> synchronously. This bridge is internal —
    /// it only ever runs on the dedicated handshake/IO thread <see cref="DtlsDatagramTransport"/> owns, never on the
    /// public async path.
    /// </para>
    /// </summary>
    sealed class BouncyCastleDatagramBridge : Org.BouncyCastle.Tls.DatagramTransport
    {
        // DTLS 1.2 records ride a single UDP datagram; 1500 (typical Ethernet MTU) bounds one record's plaintext/ciphertext.
        const int MtuLimit = 1500;

        readonly IDatagramTransport _inner;
        readonly BlockingCollection<byte[]> _inbound = new(new ConcurrentQueue<byte[]>());
        readonly CancellationTokenSource _loopCts = new();
        readonly Task _receivePump;

        public BouncyCastleDatagramBridge(IDatagramTransport inner)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _receivePump = Task.Run(() => PumpInboundAsync(_loopCts.Token));
        }

        /// <summary>Background loop: copies each inner datagram into the inbound queue until cancelled or the pipe faults.</summary>
        async Task PumpInboundAsync(CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[MtuLimit];
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    int read = await _inner.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (read <= 0) continue; // a 0-length datagram is not a close on UDP — keep listening
                    _inbound.Add(buffer.AsSpan(0, read).ToArray(), cancellationToken);
                }
            }
            catch (OperationCanceledException) { } // normal shutdown
            catch (Exception) { } // inner pipe faulted/closed — Receive will then time out and DTLS surfaces the failure
            finally { _inbound.CompleteAdding(); }
        }

        /// <inheritdoc/>
        public int GetReceiveLimit() => MtuLimit;

        /// <inheritdoc/>
        public int GetSendLimit() => MtuLimit;

        /// <inheritdoc/>
        public int Receive(byte[] buf, int off, int len, int waitMillis)
        {
            // -1 signals "no datagram within waitMillis" so BouncyCastle's flight-retransmit timer can fire.
            if (!_inbound.TryTake(out byte[]? datagram, waitMillis)) return -1;
            int n = Math.Min(len, datagram.Length);
            Buffer.BlockCopy(datagram, 0, buf, off, n);
            return n;
        }

#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
        /// <inheritdoc/>
        public int Receive(Span<byte> buffer, int waitMillis)
        {
            if (!_inbound.TryTake(out byte[]? datagram, waitMillis)) return -1;
            int n = Math.Min(buffer.Length, datagram.Length);
            datagram.AsSpan(0, n).CopyTo(buffer);
            return n;
        }
#endif

        /// <inheritdoc/>
        public void Send(byte[] buf, int off, int len)
            => _inner.SendAsync(new ReadOnlyMemory<byte>(buf, off, len)).AsTask().GetAwaiter().GetResult();

#if NETSTANDARD2_1_OR_GREATER || NET5_0_OR_GREATER
        /// <inheritdoc/>
        public void Send(ReadOnlySpan<byte> buffer)
            => Send(buffer.ToArray(), 0, buffer.Length);
#endif

        /// <inheritdoc/>
        public void Close()
        {
            try { _loopCts.Cancel(); } catch { }
            try { _receivePump.Wait(2000); } catch { }
            _loopCts.Dispose();
            _inbound.Dispose();
        }
    }
}
