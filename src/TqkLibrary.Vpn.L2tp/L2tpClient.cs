using System.Security.Cryptography;
using TqkLibrary.Vpn.L2tp.Enums;
using TqkLibrary.Vpn.L2tp.Models;

namespace TqkLibrary.Vpn.L2tp
{
    /// <summary>
    /// An L2TPv2 client (LAC side): brings up one tunnel (SCCRQ→SCCRP→SCCCN) that hosts one or more sessions
    /// (each ICRQ→ICRP→ICCN). <see cref="ConnectAsync"/> establishes the tunnel and its first session
    /// (<see cref="PrimarySession"/>); <see cref="OpenSessionAsync"/> opens additional ones on the same tunnel,
    /// each carrying an independent PPP stream. Inbound data messages are demultiplexed to the matching session.
    /// </summary>
    public sealed class L2tpClient : IDisposable
    {
        readonly IL2tpTransport _transport;
        readonly L2tpControlChannel _control;
        readonly string _hostName;
        readonly TaskCompletionSource<bool> _tunnelUp = new(TaskCreationOptions.RunContinuationsAsynchronously);

        readonly object _sessionsLock = new();
        readonly Dictionary<ushort, L2tpSession> _sessions = new(); // keyed by our LocalSessionId
        L2tpSession? _pendingSession;                               // the session whose ICRP we are awaiting (opened one at a time)
        L2tpSession? _primarySession;

        /// <summary>
        /// Creates a client over <paramref name="transport"/>; <paramref name="hostName"/> is sent as the Host Name AVP.
        /// <paramref name="retransmitOptions"/> tunes the control channel's resend interval, backoff and cap (null = default).
        /// </summary>
        public L2tpClient(IL2tpTransport transport, string hostName = "anonymous", L2tpRetransmitOptions? retransmitOptions = null)
        {
            _transport = transport;
            _hostName = hostName;
            LocalTunnelId = RandomId();
            _control = new L2tpControlChannel(transport.SendAsync, retransmitOptions);
            _control.ControlReceived += OnControl;
            _control.Failed += OnControlFailed;
            _transport.DatagramReceived += OnDatagram;
        }

        /// <summary>The tunnel id we assigned (the server addresses us with it).</summary>
        public ushort LocalTunnelId { get; }

        /// <summary>The tunnel id the server assigned (we address it with this).</summary>
        public ushort PeerTunnelId { get; private set; }

        /// <summary>The tunnel's first session, established by <see cref="ConnectAsync"/>.</summary>
        public L2tpSession PrimarySession => _primarySession ?? throw new InvalidOperationException("The L2TP tunnel has no session yet (call ConnectAsync first).");

        /// <summary>The session id we assigned for the primary session (0 before <see cref="ConnectAsync"/>).</summary>
        public ushort LocalSessionId => _primarySession?.LocalSessionId ?? 0;

        /// <summary>The session id the server assigned for the primary session (0 before <see cref="ConnectAsync"/>).</summary>
        public ushort PeerSessionId => _primarySession?.PeerSessionId ?? 0;

        /// <summary>Raised for each inbound PPP frame on the primary session (additional sessions expose their own event).</summary>
        public event Action<ReadOnlyMemory<byte>>? DataReceived;

        /// <summary>Raised when the tunnel goes down (StopCCN / control-channel failure) or the primary session is torn down (CDN).</summary>
        public event Action<string>? Disconnected;

        /// <summary>Brings up the tunnel and its first session, completing once that session is established.</summary>
        public async Task ConnectAsync(CancellationToken cancellationToken = default)
        {
            await SendSccrqAsync().ConfigureAwait(false);
            await WaitAsync(_tunnelUp.Task, cancellationToken).ConfigureAwait(false);

            L2tpSession primary = await OpenSessionInternalAsync(cancellationToken).ConfigureAwait(false);
            _primarySession = primary;
            // The primary session's data/teardown surface as the tunnel-level events so existing single-session
            // consumers (and the driver's link-loss handling) keep working unchanged.
            primary.DataReceived += frame => DataReceived?.Invoke(frame);
            primary.Disconnected += reason => Disconnected?.Invoke(reason);
        }

        /// <summary>
        /// Opens an additional session on the established tunnel (RFC 2661 ICRQ/ICRP/ICCN). Reuses the same tunnel,
        /// reliable control channel and IPsec/UDP transport. Throws if the server rejects the call with a CDN or the
        /// exchange times out — most remote-access servers permit only the single primary session.
        /// </summary>
        public Task<L2tpSession> OpenSessionAsync(CancellationToken cancellationToken = default)
            => OpenSessionInternalAsync(cancellationToken);

        async Task<L2tpSession> OpenSessionInternalAsync(CancellationToken cancellationToken)
        {
            ushort localId = NewSessionId();
            var session = new L2tpSession(this, localId);
            lock (_sessionsLock)
            {
                _sessions[localId] = session;
                _pendingSession = session;
            }

            await SendIcrqAsync(session).ConfigureAwait(false);
            try
            {
                await WaitAsync(session.Up.Task, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                lock (_sessionsLock)
                {
                    _sessions.Remove(localId);
                    if (ReferenceEquals(_pendingSession, session)) _pendingSession = null;
                }
                throw;
            }
            lock (_sessionsLock)
            {
                if (ReferenceEquals(_pendingSession, session)) _pendingSession = null;
            }
            return session;
        }

        /// <summary>Sends a PPP frame inside an L2TP data message addressed to the primary session at the server.</summary>
        public Task SendDataAsync(ReadOnlyMemory<byte> pppFrame) => PrimarySession.SendDataAsync(pppFrame);

        /// <summary>Sends a PPP frame inside an L2TP data message addressed to <paramref name="peerSessionId"/> at the server.</summary>
        internal Task SendSessionDataAsync(ushort peerSessionId, ReadOnlyMemory<byte> pppFrame)
            => _transport.SendAsync(L2tpCodec.EncodeData(PeerTunnelId, peerSessionId, pppFrame.Span));

        /// <summary>Sends an L2TP HELLO keepalive on the reliable control channel (RFC 2661 §5.5).</summary>
        public Task SendHelloAsync()
            => _control.SendAsync(L2tpControlMessage.Create(L2tpMessageType.Hello, PeerTunnelId));

        /// <summary>Sends a Call-Disconnect-Notify for the primary session (RFC 2661 §5.6); <paramref name="resultCode"/> 3 = administrative.</summary>
        public Task SendCallDisconnectAsync(ushort resultCode = 3)
        {
            L2tpSession? primary = _primarySession;
            return primary != null ? primary.SendCallDisconnectAsync(resultCode) : Task.CompletedTask;
        }

        // Sends a CDN for a specific session, addressed to the session the server assigned.
        internal Task SendCallDisconnectForAsync(L2tpSession session, ushort resultCode)
        {
            var cdn = L2tpControlMessage.Create(L2tpMessageType.CallDisconnectNotify, PeerTunnelId)
                .With(L2tpAvp.UInt16(L2tpAvpType.ResultCode, resultCode));
            cdn.SessionId = session.PeerSessionId;
            return _control.SendAsync(cdn);
        }

        /// <summary>Sends a Stop-Control-Connection-Notification to tear the tunnel down; <paramref name="resultCode"/> 1 = general request to clear.</summary>
        public Task SendStopControlConnectionAsync(ushort resultCode = 1)
            => _control.SendAsync(L2tpControlMessage.Create(L2tpMessageType.StopControlConnectionNotification, PeerTunnelId)
                .With(L2tpAvp.UInt16(L2tpAvpType.ResultCode, resultCode))
                .With(L2tpAvp.UInt16(L2tpAvpType.AssignedTunnelId, LocalTunnelId)));

        Task SendSccrqAsync()
        {
            var sccrq = L2tpControlMessage.Create(L2tpMessageType.StartControlConnectionRequest, 0)
                .With(L2tpAvp.UInt16(L2tpAvpType.ProtocolVersion, 0x0100))
                .With(L2tpAvp.UInt32(L2tpAvpType.FramingCapabilities, 3))   // async + sync
                .With(L2tpAvp.UInt32(L2tpAvpType.BearerCapabilities, 3))
                .With(L2tpAvp.Text(L2tpAvpType.HostName, _hostName))
                .With(L2tpAvp.Text(L2tpAvpType.VendorName, "TqkLibrary", mandatory: false))
                .With(L2tpAvp.UInt16(L2tpAvpType.AssignedTunnelId, LocalTunnelId))
                .With(L2tpAvp.UInt16(L2tpAvpType.ReceiveWindowSize, 8));
            return _control.SendAsync(sccrq);
        }

        Task SendScccnAsync()
            => _control.SendAsync(L2tpControlMessage.Create(L2tpMessageType.StartControlConnectionConnected, PeerTunnelId));

        Task SendIcrqAsync(L2tpSession session)
        {
            var icrq = L2tpControlMessage.Create(L2tpMessageType.IncomingCallRequest, PeerTunnelId)
                .With(L2tpAvp.UInt16(L2tpAvpType.AssignedSessionId, session.LocalSessionId))
                .With(L2tpAvp.UInt32(L2tpAvpType.CallSerialNumber, 1));
            return _control.SendAsync(icrq);
        }

        Task SendIccnAsync(L2tpSession session)
        {
            var iccn = L2tpControlMessage.Create(L2tpMessageType.IncomingCallConnected, PeerTunnelId)
                .With(L2tpAvp.UInt32(L2tpAvpType.TxConnectSpeed, 100000))
                .With(L2tpAvp.UInt32(L2tpAvpType.FramingType, 1)); // synchronous
            iccn.SessionId = session.PeerSessionId;
            return _control.SendAsync(iccn);
        }

        void OnControl(L2tpControlMessage message)
        {
            switch (message.MessageType)
            {
                case L2tpMessageType.StartControlConnectionReply:
                    L2tpAvp? tunnelId = message.Find(L2tpAvpType.AssignedTunnelId);
                    if (tunnelId != null)
                    {
                        PeerTunnelId = tunnelId.AsUInt16();
                        _control.PeerTunnelId = PeerTunnelId;
                    }
                    _ = SendScccnAsync();
                    _tunnelUp.TrySetResult(true);
                    break;

                case L2tpMessageType.IncomingCallReply:
                    // The server addresses the ICRP with the session id we assigned; fall back to the in-flight
                    // session when it echoes 0 (sessions are opened one at a time, so the pending one is unambiguous).
                    L2tpSession? opening = MatchSession(message.SessionId, fallbackToPending: true);
                    if (opening != null)
                    {
                        L2tpAvp? sessionId = message.Find(L2tpAvpType.AssignedSessionId);
                        if (sessionId != null) opening.PeerSessionId = sessionId.AsUInt16();
                        _ = SendIccnAsync(opening);
                        opening.Up.TrySetResult(true);
                    }
                    break;

                case L2tpMessageType.StopControlConnectionNotification:
                    FailTunnel("Server sent StopCCN (tunnel down).");
                    break;

                case L2tpMessageType.CallDisconnectNotify:
                    OnCallDisconnect(message.SessionId);
                    break;
            }
        }

        // A CDN tears down a single session: it rejects an in-flight open, or drops an established session. A CDN
        // addressed to the primary (or to session 0 with nothing pending) surfaces as the tunnel-level Disconnected.
        void OnCallDisconnect(ushort sessionId)
        {
            L2tpSession? target;
            lock (_sessionsLock)
            {
                if (sessionId != 0 && _sessions.TryGetValue(sessionId, out L2tpSession? matched)) target = matched;
                else target = _pendingSession ?? _primarySession;
                if (target != null)
                {
                    _sessions.Remove(target.LocalSessionId);
                    if (ReferenceEquals(_pendingSession, target)) _pendingSession = null;
                }
            }
            if (target == null) return;

            if (!target.Up.Task.IsCompleted)
                target.Up.TrySetException(new IOException("Server rejected the L2TP session (CDN)."));
            else
                target.RaiseDisconnected("Server sent CDN (call disconnected).");
        }

        // The tunnel is gone: unblock a pending connect, reject in-flight opens, and tell every session it dropped.
        void FailTunnel(string reason)
        {
            _tunnelUp.TrySetException(new IOException(reason));

            List<L2tpSession> sessions;
            lock (_sessionsLock)
            {
                sessions = new List<L2tpSession>(_sessions.Values);
                _sessions.Clear();
                _pendingSession = null;
            }
            foreach (L2tpSession session in sessions)
            {
                if (!session.Up.Task.IsCompleted) session.Up.TrySetException(new IOException(reason));
                else session.RaiseDisconnected(reason);
            }
            // Ensure the tunnel-level drop fires even if the tunnel failed before any session was established.
            if (_primarySession == null) Disconnected?.Invoke(reason);
        }

        void OnDatagram(ReadOnlyMemory<byte> datagram)
        {
            if (L2tpCodec.IsControl(datagram.Span))
            {
                _control.OnDatagram(datagram);
            }
            else if (L2tpCodec.TryDecodeData(datagram.Span, out _, out ushort sessionId, out byte[] pppFrame))
            {
                L2tpSession? session;
                lock (_sessionsLock) _sessions.TryGetValue(sessionId, out session);
                session?.RaiseData(pppFrame);
            }
        }

        // Returns the session matching the control message's header session id, optionally falling back to the
        // single in-flight session when the peer addressed it with 0 (some servers do not echo the assigned id).
        L2tpSession? MatchSession(ushort sessionId, bool fallbackToPending)
        {
            lock (_sessionsLock)
            {
                if (sessionId != 0 && _sessions.TryGetValue(sessionId, out L2tpSession? matched)) return matched;
                return fallbackToPending ? _pendingSession : null;
            }
        }

        // The reliable control channel exhausted its retransmit budget: the whole tunnel is dead — fail every session
        // and surface a tunnel-level drop (this unblocks an in-progress ConnectAsync and triggers the driver's reconnect).
        void OnControlFailed(string reason) => FailTunnel(reason);

        static async Task WaitAsync(Task task, CancellationToken cancellationToken)
        {
            var cancelled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using (cancellationToken.Register(() => cancelled.TrySetResult(true)))
            {
                Task completed = await Task.WhenAny(task, cancelled.Task).ConfigureAwait(false);
                if (completed != task)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                }
            }
            await task.ConfigureAwait(false);
        }

        // A fresh, non-zero session id distinct from every session already open on this tunnel.
        ushort NewSessionId()
        {
            lock (_sessionsLock)
            {
                ushort id;
                do { id = RandomId(); } while (_sessions.ContainsKey(id));
                return id;
            }
        }

        static ushort RandomId()
        {
            byte[] bytes = new byte[2];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            ushort id = (ushort)((bytes[0] << 8) | bytes[1]);
            return id == 0 ? (ushort)1 : id;
        }

        /// <inheritdoc/>
        public void Dispose() => _control.Dispose();
    }
}
