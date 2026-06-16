using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Ethernet.Models;

namespace TqkLibrary.VpnClient.Ethernet
{
    /// <summary>
    /// The IPv6 Neighbor Discovery implementation of <see cref="INeighborResolver"/> (RFC 4861) — the L2.4 neighbor
    /// layer of an <c>EthernetAdapter</c>, the NDISC counterpart of <see cref="ArpResolver"/>. It owns one host's MAC +
    /// IPv6 address and shares that host's switch port (<see cref="IEthernetChannel"/>) for sending NDISC traffic;
    /// inbound IPv6/ICMPv6 frames are fed in through <see cref="HandleInboundFrame"/>, which a composer wires to
    /// <see cref="VirtualHost.InboundNonIpFrame"/> — but because NDISC rides inside ordinary IPv6 (not a separate
    /// EtherType), it is also wired to <see cref="VirtualHost.InboundIpPacket"/> so it sees NS/NA/RS/RA the stack would
    /// otherwise swallow. It depends only on the Ethernet codec + <see cref="IEthernetChannel"/>, never on
    /// <see cref="VirtualHost"/>, so the two can be constructed without a cycle.
    /// <para>
    /// Egress (<see cref="ResolveAsync"/>): a neighbor-cache hit returns immediately; a miss sends a Neighbor
    /// Solicitation to the target's solicited-node multicast address (RFC 4291 §2.7.1) and awaits the NA (retried up to
    /// <see cref="NdiscResolverOptions.MaxAttempts"/>, then <c>null</c>). Concurrent resolves for the same address
    /// coalesce. Ingress (<see cref="HandleInboundFrame"/>): an NA or an NS-with-source-LLA teaches the cache and
    /// completes any pending resolve; an NS targeting our address is answered with a solicited NA; a Router
    /// Advertisement is parsed into <see cref="LastRouterAdvertisement"/> (gateway + prefix) for the SLAAC layer.
    /// </para>
    /// NDISC serves IPv6 only — IPv4 next-hops resolve to <c>null</c> (ARP is L2.3).
    /// </summary>
    public sealed class NdiscResolver : INeighborResolver, IAsyncDisposable
    {
        readonly MacAddress _mac;
        readonly IPAddress _ip;
        readonly IEthernetChannel _port;
        readonly NdiscResolverOptions _options;
        readonly object _sync = new object();
        readonly Dictionary<IPAddress, CacheEntry> _cache = new Dictionary<IPAddress, CacheEntry>();
        readonly Dictionary<IPAddress, TaskCompletionSource<MacAddress?>> _pending = new Dictionary<IPAddress, TaskCompletionSource<MacAddress?>>();
        TaskCompletionSource<bool>? _dadDefended;
        IPAddress? _dadTarget;
        RouterAdvertisementInfo? _lastRa;
        bool _disposed;

        /// <summary>
        /// Creates a resolver for the host with MAC <paramref name="mac"/> and IPv6 address <paramref name="ipv6"/>,
        /// sending NDISC traffic out <paramref name="port"/> (the same switch port its <see cref="VirtualHost"/> uses).
        /// </summary>
        public NdiscResolver(MacAddress mac, IPAddress ipv6, IEthernetChannel port, NdiscResolverOptions? options = null)
        {
            if (ipv6 is null)
                throw new ArgumentNullException(nameof(ipv6));
            if (ipv6.AddressFamily != AddressFamily.InterNetworkV6)
                throw new ArgumentException("NDISC serves an IPv6 address.", nameof(ipv6));
            _mac = mac;
            _ip = ipv6;
            _port = port ?? throw new ArgumentNullException(nameof(port));
            _options = options ?? NdiscResolverOptions.Default;
        }

        /// <summary>This host's IPv6 address (the one Neighbor Solicitations are answered for).</summary>
        public IPAddress Address => _ip;

        /// <summary>The most recent Router Advertisement parsed into gateway + prefix, or <c>null</c> if none seen yet.</summary>
        public RouterAdvertisementInfo? LastRouterAdvertisement
        {
            get { lock (_sync) return _lastRa; }
        }

        /// <summary>Raised when a Router Advertisement is received and parsed (gateway/prefix for the SLAAC layer).</summary>
        public event Action<RouterAdvertisementInfo>? RouterAdvertisementReceived;

        /// <inheritdoc/>
        public async ValueTask<ReadOnlyMemory<byte>?> ResolveAsync(IPAddress nextHop, CancellationToken cancellationToken = default)
        {
            if (_disposed || nextHop is null || nextHop.AddressFamily != AddressFamily.InterNetworkV6)
                return null;   // NDISC resolves IPv6 only; IPv4 is ARP's job (L2.3)

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
                    await SendSolicitationAsync(_ip, nextHop, cancellationToken).ConfigureAwait(false);
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
        /// Runs Duplicate Address Detection for this host's address (RFC 4862 §5.4): sends a Neighbor Solicitation from
        /// the unspecified address (::) to the address's solicited-node multicast group and waits. Returns <c>true</c>
        /// if the address is unique (no defender), <c>false</c> if a Neighbor Advertisement defends it (a duplicate).
        /// </summary>
        public async Task<bool> PerformDuplicateAddressDetectionAsync(CancellationToken cancellationToken = default)
        {
            if (_disposed)
                return true;

            var defended = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            lock (_sync)
            {
                if (_disposed)
                    return true;
                _dadDefended = defended;
                _dadTarget = _ip;
            }

            IPAddress solicited = Icmpv6Ndisc.SolicitedNodeMulticast(_ip);
            try
            {
                for (int i = 0; i < _options.DadTransmits; i++)
                {
                    if (_disposed)
                        return true;
                    // DAD source is the unspecified address (::); the Source LLA option is omitted (RFC 4861 §4.3).
                    await SendSolicitationAsync(Icmpv6Ndisc.Unspecified, _ip, solicited, cancellationToken).ConfigureAwait(false);
                    bool defendedNow = await AwaitDadAsync(defended.Task, _options.DadTimeout, cancellationToken).ConfigureAwait(false);
                    if (defendedNow)
                        return false;   // someone advertised our address → duplicate
                }
                return true;            // silence across every probe → unique
            }
            finally
            {
                lock (_sync)
                {
                    if (ReferenceEquals(_dadDefended, defended))
                    {
                        _dadDefended = null;
                        _dadTarget = null;
                    }
                }
            }
        }

        /// <summary>
        /// Feeds one inbound frame to NDISC (wired to <see cref="VirtualHost.InboundIpPacket"/> and
        /// <see cref="VirtualHost.InboundNonIpFrame"/>): if it is an IPv6 packet carrying an NDISC message, learns
        /// neighbor link-layer addresses, completes any pending resolve, answers an NS for our address, parses an RA,
        /// and flags DAD if our tentative address is defended.
        /// </summary>
        public void HandleInboundFrame(ReadOnlyMemory<byte> frame)
        {
            if (_disposed)
                return;

            // Accept either a bare IPv6 packet (the InboundIpPacket seam) or a full Ethernet frame (InboundNonIpFrame).
            ReadOnlyMemory<byte> ipv6;
            if (frame.Length >= EthernetFrame.HeaderLength && EthernetFrame.EtherType(frame.Span) == EthernetFrame.EtherTypeIpv6)
                ipv6 = EthernetFrame.Payload(frame);
            else
                ipv6 = frame;

            ReadOnlySpan<byte> packet = ipv6.Span;
            if (packet.Length < 48 || (byte)(packet[0] >> 4) != 6 || packet[6] != Icmpv6Ndisc.ProtocolNumber)
                return;   // not an IPv6 packet whose Next Header is ICMPv6

            IPAddress source = new IPAddress(packet.Slice(8, 16).ToArray());
            ReadOnlySpan<byte> message = packet.Slice(40);
            if (!Icmpv6Ndisc.IsNdisc(message))
                return;

            switch (Icmpv6Ndisc.Type(message))
            {
                case Icmpv6Ndisc.TypeNeighborAdvertisement:
                    HandleNeighborAdvertisement(source, message);
                    break;
                case Icmpv6Ndisc.TypeNeighborSolicitation:
                    HandleNeighborSolicitation(source, message);
                    break;
                case Icmpv6Ndisc.TypeRouterAdvertisement:
                    HandleRouterAdvertisement(source, message);
                    break;
                // Router Solicitation is for routers to answer; a host resolver ignores it.
            }
        }

        void HandleNeighborAdvertisement(IPAddress source, ReadOnlySpan<byte> message)
        {
            IPAddress target = Icmpv6Ndisc.TargetAddress(message);
            int optionsOffset = Icmpv6Ndisc.OptionsOffsetFor(Icmpv6Ndisc.TypeNeighborAdvertisement);
            bool hasTargetMac = Icmpv6Ndisc.TryGetLinkLayerAddress(message, optionsOffset, Icmpv6Ndisc.OptionTargetLinkLayerAddress, out MacAddress targetMac);

            MacAddress? completed = null;
            TaskCompletionSource<MacAddress?>? toComplete = null;
            TaskCompletionSource<bool>? dadDefender = null;
            lock (_sync)
            {
                if (_disposed)
                    return;
                // DAD: an NA for our tentative address (from anyone) means a duplicate.
                if (_dadDefended != null && _dadTarget != null && target.Equals(_dadTarget))
                    dadDefender = _dadDefended;

                if (hasTargetMac)
                {
                    _cache[target] = new CacheEntry(targetMac, DateTime.UtcNow + _options.CacheTtl);
                    if (_pending.TryGetValue(target, out TaskCompletionSource<MacAddress?>? tcs))
                    {
                        toComplete = tcs;
                        completed = targetMac;
                        _pending.Remove(target);
                    }
                }
            }

            dadDefender?.TrySetResult(true);   // address is defended → duplicate
            toComplete?.TrySetResult(completed);
        }

        void HandleNeighborSolicitation(IPAddress source, ReadOnlySpan<byte> message)
        {
            IPAddress target = Icmpv6Ndisc.TargetAddress(message);
            int optionsOffset = Icmpv6Ndisc.OptionsOffsetFor(Icmpv6Ndisc.TypeNeighborSolicitation);
            bool dad = source.Equals(Icmpv6Ndisc.Unspecified);

            byte[]? replyMac = null;
            TaskCompletionSource<MacAddress?>? toComplete = null;
            bool answer = false;
            lock (_sync)
            {
                if (_disposed)
                    return;
                // Learn the sender from a Source Link-Layer Address option (absent on DAD probes).
                if (!dad && Icmpv6Ndisc.TryGetLinkLayerAddress(message, optionsOffset, Icmpv6Ndisc.OptionSourceLinkLayerAddress, out MacAddress senderMac))
                {
                    _cache[source] = new CacheEntry(senderMac, DateTime.UtcNow + _options.CacheTtl);
                    if (_pending.TryGetValue(source, out TaskCompletionSource<MacAddress?>? tcs))
                    {
                        toComplete = tcs;
                        _pending.Remove(source);
                        replyMac = senderMac.ToArray();
                    }
                }
                if (target.Equals(_ip))
                    answer = true;
            }

            if (toComplete != null && replyMac != null)
                toComplete.TrySetResult(MacAddress.FromBytes(replyMac));

            if (answer)
            {
                // Solicited NA: unicast to the soliciting source (or all-nodes if this was a DAD probe from ::).
                IPAddress destination = dad ? Icmpv6Ndisc.AllNodes : source;
                byte flags = (byte)(Icmpv6Ndisc.FlagSolicited | Icmpv6Ndisc.FlagOverride);
                byte[] na = Icmpv6Ndisc.BuildNeighborAdvertisement(_ip, destination, _ip, _mac, flags);
                MacAddress dstMac = dad ? Icmpv6Ndisc.MulticastMac(Icmpv6Ndisc.AllNodes) : SenderMacOrMulticast(source, message, optionsOffset);
                byte[] ipv6 = Icmpv6Ndisc.BuildIpv6(_ip, destination, na);
                byte[] ethernetFrame = EthernetFrame.Build(dstMac, _mac, EthernetFrame.EtherTypeIpv6, ipv6);
                // Sent outside the lock (switch pattern): the in-memory fabric delivers inline, so holding the lock
                // would risk a re-entrant deadlock. Fire-and-forget; the in-memory channel completes synchronously.
                _ = _port.WriteFrameAsync(ethernetFrame);
            }
        }

        void HandleRouterAdvertisement(IPAddress source, ReadOnlySpan<byte> message)
        {
            int optionsOffset = Icmpv6Ndisc.OptionsOffsetFor(Icmpv6Ndisc.TypeRouterAdvertisement);
            MacAddress? routerMac = Icmpv6Ndisc.TryGetLinkLayerAddress(message, optionsOffset, Icmpv6Ndisc.OptionSourceLinkLayerAddress, out MacAddress rMac)
                ? rMac
                : (MacAddress?)null;
            byte raFlags = Icmpv6Ndisc.RaFlags(message);
            ushort routerLifetime = Icmpv6Ndisc.RouterLifetime(message);

            IPAddress? prefix = null;
            byte prefixLength = 0;
            bool onLink = false, autonomous = false;
            uint validLifetime = 0, preferredLifetime = 0;
            if (Icmpv6Ndisc.TryGetPrefixInformation(message, out IPAddress p, out byte pLen, out byte pFlags, out uint valid, out uint preferred))
            {
                prefix = p;
                prefixLength = pLen;
                onLink = (pFlags & Icmpv6Ndisc.PrefixFlagOnLink) != 0;
                autonomous = (pFlags & Icmpv6Ndisc.PrefixFlagAutonomous) != 0;
                validLifetime = valid;
                preferredLifetime = preferred;
            }

            var info = new RouterAdvertisementInfo(
                source, routerMac, routerLifetime,
                (raFlags & Icmpv6Ndisc.RaFlagManaged) != 0,
                (raFlags & Icmpv6Ndisc.RaFlagOther) != 0,
                prefix, prefixLength, onLink, autonomous, validLifetime, preferredLifetime);

            lock (_sync)
            {
                if (_disposed)
                    return;
                _lastRa = info;
                if (routerMac.HasValue)
                    _cache[source] = new CacheEntry(routerMac.Value, DateTime.UtcNow + _options.CacheTtl);   // learn the router too
            }
            RouterAdvertisementReceived?.Invoke(info);
        }

        ValueTask SendSolicitationAsync(IPAddress source, IPAddress target, CancellationToken cancellationToken)
            => SendSolicitationAsync(source, target, Icmpv6Ndisc.SolicitedNodeMulticast(target), cancellationToken);

        ValueTask SendSolicitationAsync(IPAddress source, IPAddress target, IPAddress destination, CancellationToken cancellationToken)
        {
            byte[] ns = Icmpv6Ndisc.BuildNeighborSolicitation(source, destination, target, _mac);
            byte[] ipv6 = Icmpv6Ndisc.BuildIpv6(source, destination, ns);
            MacAddress dstMac = Icmpv6Ndisc.MulticastMac(destination);   // NS goes to the solicited-node multicast MAC
            byte[] frame = EthernetFrame.Build(dstMac, _mac, EthernetFrame.EtherTypeIpv6, ipv6);
            return _port.WriteFrameAsync(frame, cancellationToken);
        }

        MacAddress SenderMacOrMulticast(IPAddress source, ReadOnlySpan<byte> message, int optionsOffset)
        {
            if (Icmpv6Ndisc.TryGetLinkLayerAddress(message, optionsOffset, Icmpv6Ndisc.OptionSourceLinkLayerAddress, out MacAddress senderMac))
                return senderMac;
            lock (_sync)
            {
                if (_cache.TryGetValue(source, out CacheEntry entry))
                    return entry.Mac;
            }
            return Icmpv6Ndisc.MulticastMac(Icmpv6Ndisc.AllNodes);   // last resort: flood
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

        /// <summary>Awaits a DAD defence but gives up after <paramref name="timeout"/> (returns <c>false</c> — no defender).</summary>
        static async Task<bool> AwaitDadAsync(Task<bool> defendedTask, TimeSpan timeout, CancellationToken cancellationToken)
        {
            if (defendedTask.IsCompleted)
                return await defendedTask.ConfigureAwait(false);
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            Task delay = Task.Delay(timeout, timeoutCts.Token);
            Task winner = await Task.WhenAny(defendedTask, delay).ConfigureAwait(false);
            if (winner == defendedTask)
            {
                timeoutCts.Cancel();
                return await defendedTask.ConfigureAwait(false);
            }
            cancellationToken.ThrowIfCancellationRequested();
            return false;   // no defender within the window → unique
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            List<TaskCompletionSource<MacAddress?>> pending;
            TaskCompletionSource<bool>? dad;
            lock (_sync)
            {
                if (_disposed)
                    return default;
                _disposed = true;
                pending = new List<TaskCompletionSource<MacAddress?>>(_pending.Values);
                _pending.Clear();
                _cache.Clear();
                dad = _dadDefended;
                _dadDefended = null;
                _dadTarget = null;
            }
            foreach (TaskCompletionSource<MacAddress?> tcs in pending)
                tcs.TrySetResult(null);   // release any in-flight resolves
            dad?.TrySetResult(false);     // release any in-flight DAD (treat as unique)
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
