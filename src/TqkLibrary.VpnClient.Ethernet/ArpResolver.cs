using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// The IPv4 ARP implementation of <see cref="INeighborResolver"/> (RFC 826) — the L2.3 neighbor layer of an
    /// <c>EthernetAdapter</c>. It owns one host's MAC + IPv4 address and shares that host's switch port
    /// (<see cref="IEthernetChannel"/>) for sending ARP traffic; inbound ARP frames are fed in through
    /// <see cref="HandleInboundFrame"/>, which a composer wires to <see cref="VirtualHost.InboundNonIpFrame"/>
    /// (the non-IP seam built in L2.2). It depends only on the Ethernet codec + <see cref="IEthernetChannel"/>,
    /// never on <see cref="VirtualHost"/>, so the two can be constructed without a cycle.
    /// <para>
    /// Egress (<see cref="ResolveAsync"/>): a cache hit returns immediately; a miss broadcasts an ARP request and
    /// awaits the reply (retried up to <see cref="ArpResolverOptions.MaxAttempts"/>, then <c>null</c>). Concurrent
    /// resolves for the same address coalesce onto one request. Ingress (<see cref="HandleInboundFrame"/>): every ARP
    /// packet teaches the cache sender-IP→MAC and completes any pending resolve; an ARP request that targets our IP is
    /// answered with a unicast reply. ARP serves IPv4 only — IPv6 next-hops resolve to <c>null</c> (NDISC is L2.4).
    /// </para>
    /// </summary>
    public sealed class ArpResolver : INeighborResolver, IAsyncDisposable
    {
        readonly MacAddress _mac;
        IPAddress _ip;
        readonly IEthernetChannel _port;
        readonly ArpResolverOptions _options;
        readonly object _sync = new object();
        readonly Dictionary<IPAddress, CacheEntry> _cache = new Dictionary<IPAddress, CacheEntry>();
        readonly Dictionary<IPAddress, TaskCompletionSource<MacAddress?>> _pending = new Dictionary<IPAddress, TaskCompletionSource<MacAddress?>>();
        bool _disposed;

        /// <summary>
        /// Creates a resolver for the host with MAC <paramref name="mac"/> and IPv4 address <paramref name="ipv4"/>,
        /// sending ARP traffic out <paramref name="port"/> (the same switch port its <see cref="VirtualHost"/> uses).
        /// </summary>
        public ArpResolver(MacAddress mac, IPAddress ipv4, IEthernetChannel port, ArpResolverOptions? options = null)
        {
            if (ipv4 is null)
                throw new ArgumentNullException(nameof(ipv4));
            if (ipv4.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("ARP serves an IPv4 address.", nameof(ipv4));
            _mac = mac;
            _ip = ipv4;
            _port = port ?? throw new ArgumentNullException(nameof(port));
            _options = options ?? ArpResolverOptions.Default;
        }

        /// <summary>This host's IPv4 address (the one ARP requests are answered for).</summary>
        public IPAddress Address => _ip;

        /// <summary>
        /// Updates this host's IPv4 address — the address ARP requests are now answered for and the sender-IP of outbound
        /// ARP requests. Used when the address is only known after a DHCP lease (a station attached before it leased) or
        /// when a renewal changes it. The cache is left intact (learned neighbour entries are unaffected).
        /// </summary>
        /// <exception cref="ArgumentException"><paramref name="ipv4"/> is not an IPv4 address.</exception>
        public void SetLocalAddress(IPAddress ipv4)
        {
            if (ipv4 is null)
                throw new ArgumentNullException(nameof(ipv4));
            if (ipv4.AddressFamily != AddressFamily.InterNetwork)
                throw new ArgumentException("ARP serves an IPv4 address.", nameof(ipv4));
            lock (_sync)
                _ip = ipv4;
        }

        /// <inheritdoc/>
        public async ValueTask<ReadOnlyMemory<byte>?> ResolveAsync(IPAddress nextHop, CancellationToken cancellationToken = default)
        {
            if (_disposed || nextHop is null || nextHop.AddressFamily != AddressFamily.InterNetwork)
                return null;   // ARP resolves IPv4 only; IPv6 is NDISC's job (L2.4)

            TaskCompletionSource<MacAddress?> tcs;
            bool isOwner;
            lock (_sync)
            {
                if (_disposed)
                    return null;
                if (_cache.TryGetValue(nextHop, out CacheEntry entry) && entry.Expiry > DateTime.UtcNow)
                    return entry.Mac.ToArray();
                if (_pending.TryGetValue(nextHop, out TaskCompletionSource<MacAddress?>? existing))
                {
                    tcs = existing;
                    isOwner = false;
                }
                else
                {
                    // RunContinuationsAsynchronously: completing the TCS from an inbound handler must not run this
                    // resolve's continuation inline (it could re-enter the synchronous switch deliver path).
                    tcs = new TaskCompletionSource<MacAddress?>(TaskCreationOptions.RunContinuationsAsynchronously);
                    _pending[nextHop] = tcs;
                    isOwner = true;
                }
            }

            if (!isOwner)
            {
                MacAddress? shared = await tcs.Task.ConfigureAwait(false);
                return shared.HasValue ? shared.Value.ToArray() : (ReadOnlyMemory<byte>?)null;
            }

            try
            {
                for (int attempt = 0; attempt < _options.MaxAttempts; attempt++)
                {
                    if (_disposed)
                        return null;
                    await SendRequestAsync(nextHop, cancellationToken).ConfigureAwait(false);
                    MacAddress? resolved = await AwaitReplyAsync(tcs.Task, _options.RequestTimeout, cancellationToken).ConfigureAwait(false);
                    if (resolved.HasValue)
                        return resolved.Value.ToArray();
                }
                CompletePending(nextHop, null);   // exhausted attempts: release waiters with null
                return null;
            }
            catch
            {
                CompletePending(nextHop, null);   // cancellation / send failure: never leave waiters hanging
                throw;
            }
        }

        /// <summary>
        /// Feeds one inbound non-IP frame to ARP (wired to <see cref="VirtualHost.InboundNonIpFrame"/>): learns the
        /// sender's IP→MAC, completes any pending resolve for it, and replies to a request that targets our IP.
        /// </summary>
        public void HandleInboundFrame(ReadOnlyMemory<byte> frame)
        {
            if (_disposed || frame.Length < EthernetFrame.HeaderLength)
                return;
            if (EthernetFrame.EtherType(frame.Span) != EthernetFrame.EtherTypeArp)
                return;
            ReadOnlySpan<byte> arp = EthernetFrame.Payload(frame).Span;
            if (!ArpPacket.IsIpv4OverEthernet(arp))
                return;

            ushort operation = ArpPacket.Operation(arp);
            MacAddress senderMac = ArpPacket.SenderMac(arp);
            IPAddress senderIp = ArpPacket.SenderIp(arp);
            IPAddress targetIp = ArpPacket.TargetIp(arp);

            TaskCompletionSource<MacAddress?>? toComplete = null;
            bool answerRequest = false;
            lock (_sync)
            {
                if (_disposed)
                    return;
                _cache[senderIp] = new CacheEntry(senderMac, DateTime.UtcNow + _options.CacheTtl);   // learn from any ARP (RFC 826 merge)
                if (_pending.TryGetValue(senderIp, out TaskCompletionSource<MacAddress?>? tcs))
                {
                    toComplete = tcs;
                    _pending.Remove(senderIp);
                }
                if (operation == ArpPacket.OperationRequest && targetIp.Equals(_ip))
                    answerRequest = true;
            }

            toComplete?.TrySetResult(senderMac);

            if (answerRequest)
            {
                byte[] reply = EthernetFrame.Build(senderMac, _mac, EthernetFrame.EtherTypeArp,
                    ArpPacket.BuildReply(_mac, _ip, senderMac, senderIp));
                // Sent outside the lock (switch pattern): the in-memory fabric delivers inline, so holding the lock
                // would risk a re-entrant deadlock. This is a void event handler, so the write is fire-and-forget;
                // the in-memory channel completes it synchronously.
                _ = _port.WriteFrameAsync(reply);
            }
        }

        ValueTask SendRequestAsync(IPAddress targetIp, CancellationToken cancellationToken)
        {
            byte[] frame = EthernetFrame.Build(MacAddress.Broadcast, _mac, EthernetFrame.EtherTypeArp,
                ArpPacket.BuildRequest(_mac, _ip, targetIp));
            return _port.WriteFrameAsync(frame, cancellationToken);
        }

        void CompletePending(IPAddress nextHop, MacAddress? result)
        {
            TaskCompletionSource<MacAddress?>? tcs;
            lock (_sync)
            {
                if (_pending.TryGetValue(nextHop, out tcs))
                    _pending.Remove(nextHop);
            }
            tcs?.TrySetResult(result);
        }

        /// <summary>Awaits <paramref name="replyTask"/> but gives up after <paramref name="timeout"/> (returns <c>null</c>).</summary>
        static async Task<MacAddress?> AwaitReplyAsync(Task<MacAddress?> replyTask, TimeSpan timeout, CancellationToken cancellationToken)
        {
            if (replyTask.IsCompleted)
                return await replyTask.ConfigureAwait(false);
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            Task delay = Task.Delay(timeout, timeoutCts.Token);
            Task winner = await Task.WhenAny(replyTask, delay).ConfigureAwait(false);
            if (winner == replyTask)
            {
                timeoutCts.Cancel();   // release the pending delay timer
                return await replyTask.ConfigureAwait(false);
            }
            cancellationToken.ThrowIfCancellationRequested();   // delay fired due to cancellation, not a timeout
            return null;
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            List<TaskCompletionSource<MacAddress?>> pending;
            lock (_sync)
            {
                if (_disposed)
                    return default;
                _disposed = true;
                pending = new List<TaskCompletionSource<MacAddress?>>(_pending.Values);
                _pending.Clear();
                _cache.Clear();
            }
            foreach (TaskCompletionSource<MacAddress?> tcs in pending)
                tcs.TrySetResult(null);   // release any in-flight resolves
            return default;
        }

        readonly struct CacheEntry
        {
            public readonly MacAddress Mac;
            public readonly DateTime Expiry;

            public CacheEntry(MacAddress mac, DateTime expiry)
            {
                Mac = mac;
                Expiry = expiry;
            }
        }
    }
}
