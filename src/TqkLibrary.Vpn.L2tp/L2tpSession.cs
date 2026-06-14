namespace TqkLibrary.Vpn.L2tp
{
    /// <summary>
    /// One call (PPP session) inside an L2TP tunnel (RFC 2661 §3.3): its own Session ID pair, data demux and CDN.
    /// A tunnel hosts one or more of these; the first is the <see cref="L2tpClient.PrimarySession"/>, additional ones
    /// are opened with <see cref="L2tpClient.OpenSessionAsync"/>. Outbound data and teardown are delegated to the
    /// owning <see cref="L2tpClient"/> (the reliable control channel and the UDP transport are tunnel-wide).
    /// </summary>
    public sealed class L2tpSession
    {
        readonly L2tpClient _client;

        // Completes when the session's ICRP is received (ICCN sent), or faults if the server rejects it with a CDN.
        internal TaskCompletionSource<bool> Up { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        internal L2tpSession(L2tpClient client, ushort localSessionId)
        {
            _client = client;
            LocalSessionId = localSessionId;
        }

        /// <summary>The session id we assigned (the server addresses our session with it).</summary>
        public ushort LocalSessionId { get; }

        /// <summary>The session id the server assigned, learned from its ICRP (we address it with this).</summary>
        public ushort PeerSessionId { get; internal set; }

        /// <summary>Raised for each inbound PPP frame carried by an L2TP data message for this session.</summary>
        public event Action<ReadOnlyMemory<byte>>? DataReceived;

        /// <summary>Raised when this session is torn down after it was established (the server sent a CDN for it).</summary>
        public event Action<string>? Disconnected;

        /// <summary>Sends a PPP frame inside an L2TP data message addressed to this session at the server.</summary>
        public Task SendDataAsync(ReadOnlyMemory<byte> pppFrame) => _client.SendSessionDataAsync(PeerSessionId, pppFrame);

        /// <summary>Sends a Call-Disconnect-Notify for this session (RFC 2661 §5.6); <paramref name="resultCode"/> 3 = administrative.</summary>
        public Task SendCallDisconnectAsync(ushort resultCode = 3) => _client.SendCallDisconnectForAsync(this, resultCode);

        internal void RaiseData(ReadOnlyMemory<byte> frame) => DataReceived?.Invoke(frame);

        internal void RaiseDisconnected(string reason) => Disconnected?.Invoke(reason);
    }
}
