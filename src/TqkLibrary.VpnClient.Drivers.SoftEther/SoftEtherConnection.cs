using System.Collections.Generic;
using System.Net;
using TqkLibrary.VpnClient.Abstractions.Channels;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Crypto;
using TqkLibrary.VpnClient.Drivers.SoftEther.Enums;
using TqkLibrary.VpnClient.Drivers.SoftEther.Models;
using TqkLibrary.VpnClient.Drivers.SoftEther.Transport;
using TqkLibrary.VpnClient.Ethernet;
using TqkLibrary.VpnClient.SoftEther;
using TqkLibrary.VpnClient.SoftEther.DataChannel;
using TqkLibrary.VpnClient.SoftEther.Models;

namespace TqkLibrary.VpnClient.Drivers.SoftEther
{
    /// <summary>
    /// A complete SoftEther SSL-VPN client over a single TLS byte stream. It runs the control handshake
    /// (<see cref="SoftEtherHandshake"/>: watermark → hello → login → welcome), then switches the same stream into the
    /// data session — "Ethernet over HTTPS". The data session is exposed as an L2 <see cref="SoftEtherEthernetChannel"/>
    /// that is bridged down to a bare L3 <see cref="IPacketChannel"/> through the userspace Ethernet fabric: a
    /// <see cref="DhcpV4Configurator"/> (L2.5) leases an IP from the server's SecureNAT, then an <see cref="ArpResolver"/>
    /// (L2.3) + <see cref="VirtualHost"/> (L2.2) carry IP traffic — the IP stack binds the stable facade, never the
    /// Ethernet channel. A receive loop decodes inbound data blocks and dispatches frames; a periodic keep-alive runs
    /// for the session's lifetime, and (when enabled) a dropped session is re-established behind the same facade,
    /// mirroring the OpenVPN / WireGuard drivers. Not a server — the responder role lives only in tests.
    /// </summary>
    public sealed class SoftEtherConnection : IDisposable, IAsyncDisposable
    {
        static readonly TimeSpan KeepAliveTick = TimeSpan.FromSeconds(5);

        readonly string _host;
        readonly int _port;
        readonly SoftEtherLoginRequest _login;
        readonly ISoftEtherTransportFactory _transportFactory;
        readonly SoftEtherReconnectOptions _opts;
        readonly AddressFamilyPreference _addressFamilyPreference;
        readonly SoftEtherWatermark? _watermark;
        readonly DhcpV4ConfiguratorOptions? _dhcpOptions;
        readonly int _mtu;

        readonly SwappablePacketChannel _facade = new();
        readonly CancellationTokenSource _lifetimeCts = new();
        readonly Random _random = new();
        readonly MacAddress _mac;              // a stable locally-administered MAC kept across reconnects
        readonly object _stateLock = new();

        IPAddress? _assignedAddress;
        IPAddress? _lastAssignedAddress;
        TunnelConfig _config = new();

        IByteStreamTransport? _transport;
        SoftEtherEthernetChannel? _channel;
        VirtualHost? _host2;                   // the L2↔L3 bridge whose IPacketChannel feeds the facade
        ArpResolver? _arp;                     // IPv4 neighbour resolver sharing the data channel
        DhcpV4Configurator? _dhcp;             // the DHCPv4 client (drains inbound DHCP during/after the lease)
        CancellationTokenSource? _loopCts;
        Task? _receiveTask;
        System.Threading.Timer? _keepAliveTimer;

        volatile bool _running;
        volatile bool _userTeardown;
        bool _supervisorActive;                // guarded by _stateLock
        Task? _supervisor;
        SoftEtherConnectionState _state = SoftEtherConnectionState.Disconnected;

        /// <summary>
        /// Creates a connection. <paramref name="login"/> carries the hub/user/credential + session params;
        /// <paramref name="transportFactory"/> opens the TLS byte stream (an in-process factory drives it offline);
        /// <paramref name="watermark"/> overrides the watermark POST blob (e.g. the genuine server blob);
        /// <paramref name="dhcpOptions"/> tunes the DHCPv4 exchange.
        /// </summary>
        public SoftEtherConnection(string host, int port, SoftEtherLoginRequest login,
            ISoftEtherTransportFactory transportFactory,
            SoftEtherReconnectOptions? reconnectOptions = null,
            AddressFamilyPreference addressFamilyPreference = AddressFamilyPreference.Auto,
            SoftEtherWatermark? watermark = null,
            DhcpV4ConfiguratorOptions? dhcpOptions = null,
            int mtu = 1500)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _port = port;
            _login = login ?? throw new ArgumentNullException(nameof(login));
            _transportFactory = transportFactory ?? throw new ArgumentNullException(nameof(transportFactory));
            _opts = reconnectOptions ?? new SoftEtherReconnectOptions();
            _addressFamilyPreference = addressFamilyPreference;
            _watermark = watermark;
            _dhcpOptions = dhcpOptions;
            if (mtu < 1) throw new ArgumentOutOfRangeException(nameof(mtu));
            _mtu = mtu;
            _mac = GenerateLocalMac(_random);
        }

        // A locally-administered unicast MAC for the virtual L2 endpoint: clear the I/G (multicast) bit and set the
        // U/L (locally-administered) bit of octet 0, the rest random — what a software NIC does.
        static MacAddress GenerateLocalMac(Random random)
        {
            byte[] bytes = new byte[MacAddress.Size];
            random.NextBytes(bytes);
            bytes[0] = (byte)((bytes[0] & 0xFE) | 0x02);
            return MacAddress.FromBytes(bytes);
        }

        /// <summary>The stable L3 packet channel (valid after a successful connect; survives reconnect).</summary>
        public IPacketChannel PacketChannel => _facade;

        /// <summary>The tunnel configuration leased over DHCP (address, prefix, DNS, routes, MTU).</summary>
        public TunnelConfig Config => _config;

        /// <summary>The tunnel IP leased over DHCP (valid after connect).</summary>
        public IPAddress AssignedAddress => _assignedAddress ?? IPAddress.Any;

        /// <summary>This endpoint's virtual MAC address on the SoftEther L2 segment.</summary>
        public MacAddress LinkAddress => _mac;

        /// <summary>Raised whenever the connection state changes (handshake progress, drop, reconnect).</summary>
        public event Action<SoftEtherConnectionState>? StateChanged;

        /// <summary>Raised after a successful auto-reconnect, carrying the new address and whether it changed.</summary>
        public event Action<SoftEtherReconnectInfo>? Reconnected;

        /// <summary>The current lifecycle state.</summary>
        public SoftEtherConnectionState State => _state;

        /// <summary>Runs the full handshake + DHCP lease and returns once the tunnel is carrying traffic.</summary>
        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            SetState(SoftEtherConnectionState.Connecting);
            await EstablishAsync(cancellationToken).ConfigureAwait(false);
            _lastAssignedAddress = _assignedAddress;
        }

        // ---- one full tunnel attempt (reused by the first connect and every reconnect) ----

        async Task EstablishAsync(CancellationToken cancellationToken)
        {
            await CleanupAttemptResourcesAsync().ConfigureAwait(false);

            _loopCts = CancellationTokenSource.CreateLinkedTokenSource(_lifetimeCts.Token, cancellationToken);
            CancellationToken loopToken = _loopCts.Token;

            // --- TLS + control handshake (watermark → hello → login → welcome) over one byte stream ---
            IByteStreamTransport transport = await _transportFactory
                .ConnectAsync(_host, _port, _addressFamilyPreference, cancellationToken).ConfigureAwait(false);
            _transport = transport;
            await transport.ConnectAsync(cancellationToken).ConfigureAwait(false);

            var handshake = new SoftEtherHandshake(new SoftEtherAuth(new Sha0()), _random);
            await handshake.RunAsync(transport, _host, _login, _watermark, cancellationToken).ConfigureAwait(false);

            // --- the stream is now the data session: expose it as an L2 channel and start decoding inbound blocks ---
            var channel = new SoftEtherEthernetChannel(_mac.ToArray(), SendBlockAsync, _mtu);
            _channel = channel;
            _running = true;
            _receiveTask = Task.Run(() => ReceiveLoopAsync(transport, channel, loopToken));

            // --- DHCP lease (SecureNAT) over the L2 segment: DHCP shares the channel and drains inbound DHCP replies ---
            var dhcp = new DhcpV4Configurator(_mac, channel, _dhcpOptions);
            _dhcp = dhcp;
            channel.InboundFrame += dhcp.HandleInboundFrame;   // feed inbound frames to DHCP for the OFFER/ACK
            TunnelConfig config;
            try
            {
                config = await dhcp.ConfigureAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                channel.InboundFrame -= dhcp.HandleInboundFrame;
            }

            if (config.AssignedAddress is null || config.AssignedAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                throw new VpnConnectionException("SoftEther DHCP did not lease an IPv4 address (SecureNAT serves IPv4 via DHCP; ARP is IPv4-only).");

            // --- bring up the L2↔L3 bridge on the leased address; the IP stack binds the facade, never the channel ---
            var arp = new ArpResolver(_mac, config.AssignedAddress, channel);
            var virtualHost = new VirtualHost(_mac, channel, arp);
            virtualHost.InboundNonIpFrame += arp.HandleInboundFrame;     // ARP replies/requests arrive on the non-IP seam
            virtualHost.InboundIpPacket += dhcp.HandleInboundFrame;      // a renewal DHCP reply rides ordinary IPv4
            _arp = arp;
            _host2 = virtualHost;

            config.Mtu = virtualHost.Mtu;                               // link − 14: the bound stack clamps MSS for the Ethernet header
            _config = config;
            _assignedAddress = config.AssignedAddress;
            _facade.SetInner(virtualHost);

            StartKeepAlive();
            SetState(SoftEtherConnectionState.Connected);
        }

        // ---- write side: seal a data block and push it down the TLS transport ----

        ValueTask SendBlockAsync(ReadOnlyMemory<byte> block, CancellationToken cancellationToken)
        {
            IByteStreamTransport? transport = _transport;
            return transport?.WriteAsync(block, cancellationToken) ?? default;
        }

        // ---- receive loop: decode inbound data blocks and dispatch each frame to the channel ----

        async Task ReceiveLoopAsync(IByteStreamTransport transport, SoftEtherEthernetChannel channel, CancellationToken cancellationToken)
        {
            var reader = new SoftEtherDataBlockReader(transport);
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    IReadOnlyList<byte[]> frames = await reader.ReadBlockAsync(cancellationToken).ConfigureAwait(false);
                    if (frames.Count == 0)
                    {
                        OnLinkLost("SoftEther server closed the data session.");
                        return;
                    }
                    for (int i = 0; i < frames.Count; i++)
                        channel.Deliver(frames[i]);   // keep-alive frames are dropped inside Deliver
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { /* teardown */ }
            catch (Exception)
            {
                OnLinkLost("SoftEther data session faulted while reading.");
            }
        }

        // ---- keep-alive: send the SoftEther idle keep-alive frame periodically so the session stays open ----

        void StartKeepAlive()
            => _keepAliveTimer = new System.Threading.Timer(_ => _ = KeepAliveTickAsync(), null, KeepAliveTick, KeepAliveTick);

        async Task KeepAliveTickAsync()
        {
            if (!_running) return;
            IByteStreamTransport? transport = _transport;
            if (transport is null) return;
            try
            {
                byte[] block = SoftEtherDataFrameCodec.EncodeSingle(SoftEtherDataConstants.KeepAliveBytes);
                await transport.WriteAsync(block).ConfigureAwait(false);
            }
            catch { /* a missed keep-alive is harmless; the receive loop trips link-loss if the peer goes away */ }
        }

        // ---- link-loss handling + auto-reconnect supervisor (mirrors the OpenVPN / WireGuard driver) ----

        void OnLinkLost(string reason)
        {
            bool goDisconnected = false;
            bool startSupervisor = false;
            lock (_stateLock)
            {
                if (!_running) return;
                _running = false;
                StopKeepAlive();

                if (_userTeardown || !_opts.Enabled)
                    goDisconnected = true;
                else if (!_supervisorActive)
                {
                    _supervisorActive = true;
                    startSupervisor = true;
                }
            }

            if (goDisconnected) { SetState(SoftEtherConnectionState.Disconnected); return; }
            if (startSupervisor)
            {
                SetState(SoftEtherConnectionState.Reconnecting);
                _supervisor = Task.Run(() => ReconnectLoopAsync(_lifetimeCts.Token));
            }
        }

        async Task ReconnectLoopAsync(CancellationToken cancellationToken)
        {
            TimeSpan delay = _opts.InitialBackoff;
            int failures = 0;
            while (!_userTeardown && !cancellationToken.IsCancellationRequested)
            {
                bool established = false;
                try { await EstablishAsync(cancellationToken).ConfigureAwait(false); established = true; }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
                catch { /* attempt failed — back off and retry */ }

                if (established)
                {
                    bool healthy;
                    lock (_stateLock)
                    {
                        healthy = _running;
                        if (healthy) _supervisorActive = false;
                    }
                    if (healthy) { RaiseReconnected(); return; }

                    SetState(SoftEtherConnectionState.Reconnecting);
                    delay = _opts.InitialBackoff;
                    failures = 0;
                    continue;
                }

                if (_opts.MaxAttempts != 0 && ++failures >= _opts.MaxAttempts) break;
                try { await Task.Delay(WithJitter(delay), cancellationToken).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
                delay = _opts.NextBackoff(delay);
            }

            lock (_stateLock) { _supervisorActive = false; }
            if (!_userTeardown) SetState(SoftEtherConnectionState.Disconnected);
        }

        void RaiseReconnected()
        {
            IPAddress newAddress = _assignedAddress ?? IPAddress.Any;
            bool changed = _lastAssignedAddress != null && !newAddress.Equals(_lastAssignedAddress);
            _lastAssignedAddress = newAddress;
            Reconnected?.Invoke(new SoftEtherReconnectInfo(newAddress, changed));
        }

        // ---- teardown ----

        /// <summary>
        /// Tears the tunnel down permanently (no reconnect): cancels any reconnect in flight, then cancels the receive
        /// loop and disposes the transport. Best-effort and time-boxed; safe to call more than once.
        /// </summary>
        public async Task DisconnectAsync(CancellationToken cancellationToken = default)
        {
            _userTeardown = true;
            lock (_stateLock) { _running = false; StopKeepAlive(); }

            _lifetimeCts.Cancel();
            Task? supervisor = _supervisor;
            if (supervisor != null) { try { await supervisor.ConfigureAwait(false); } catch { } }

            await CleanupAttemptResourcesAsync().ConfigureAwait(false);
            SetState(SoftEtherConnectionState.Disconnected);
        }

        async Task CleanupAttemptResourcesAsync()
        {
            _running = false;
            StopKeepAlive();

            CancellationTokenSource? loop = _loopCts;
            _loopCts = null;
            try { loop?.Cancel(); } catch { }

            Task? receive = _receiveTask;
            _receiveTask = null;
            if (receive != null) { try { await receive.ConfigureAwait(false); } catch { } }
            loop?.Dispose();

            // L2 fabric: disposing the host detaches + disposes the channel; the resolver/DHCP release any pending work.
            VirtualHost? host2 = _host2;
            _host2 = null;
            if (host2 != null) { try { await host2.DisposeAsync().ConfigureAwait(false); } catch { } }

            ArpResolver? arp = _arp;
            _arp = null;
            if (arp != null) { try { await arp.DisposeAsync().ConfigureAwait(false); } catch { } }

            DhcpV4Configurator? dhcp = _dhcp;
            _dhcp = null;
            if (dhcp != null) { try { await dhcp.DisposeAsync().ConfigureAwait(false); } catch { } }

            SoftEtherEthernetChannel? channel = _channel;
            _channel = null;
            if (channel != null && host2 is null) { try { await channel.DisposeAsync().ConfigureAwait(false); } catch { } }

            IByteStreamTransport? transport = _transport;
            _transport = null;
            if (transport != null) { try { await transport.DisposeAsync().ConfigureAwait(false); } catch { } }
        }

        void StopKeepAlive()
        {
            _keepAliveTimer?.Dispose();
            _keepAliveTimer = null;
        }

        // ---- helpers ----

        TimeSpan WithJitter(TimeSpan delay)
        {
            double fraction = _opts.JitterFraction;
            if (fraction <= 0) return delay;
            double r;
            lock (_random) r = _random.NextDouble();
            double jitter = delay.TotalMilliseconds * fraction * (r * 2 - 1);
            return TimeSpan.FromMilliseconds(Math.Max(0, delay.TotalMilliseconds + jitter));
        }

        void SetState(SoftEtherConnectionState state)
        {
            if (_state == state) return;
            _state = state;
            StateChanged?.Invoke(state);
        }

        /// <inheritdoc/>
        public async ValueTask DisposeAsync()
        {
            try { await DisconnectAsync().ConfigureAwait(false); } catch { }
            _lifetimeCts.Dispose();
            await _facade.DisposeAsync().ConfigureAwait(false);
        }

        /// <inheritdoc/>
        public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();
    }
}
