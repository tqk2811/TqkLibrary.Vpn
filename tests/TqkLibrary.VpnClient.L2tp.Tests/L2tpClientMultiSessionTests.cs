using System.Collections.Concurrent;
using TqkLibrary.VpnClient.L2tp;
using TqkLibrary.VpnClient.L2tp.Enums;
using TqkLibrary.VpnClient.L2tp.Models;
using Xunit;

namespace TqkLibrary.VpnClient.L2tp.Tests
{
    /// <summary>
    /// Drives <see cref="L2tpClient"/> opening a second session on one tunnel (RFC 2661 multi-session): distinct
    /// session ids, per-session inbound data demux, and a server that rejects the extra call with a CDN.
    /// </summary>
    public class L2tpClientMultiSessionTests
    {
        [Fact]
        public async Task OpenSession_SecondCallOnSameTunnel_GetsDistinctIds_AndDemuxesData()
        {
            var link = new LoopbackLink();
            var lns = new MultiSessionLns(link.Server, rejectExtra: false);
            var client = new L2tpClient(link.Client, retransmitOptions: new L2tpRetransmitOptions { Interval = TimeSpan.FromSeconds(30) });

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await client.ConnectAsync(cts.Token);
            L2tpSession primary = client.PrimarySession;
            L2tpSession second = await client.OpenSessionAsync(cts.Token);

            // One tunnel, two distinct calls.
            Assert.NotEqual(primary.LocalSessionId, second.LocalSessionId);
            Assert.NotEqual(primary.PeerSessionId, second.PeerSessionId);
            Assert.NotEqual(0, second.PeerSessionId);

            string? onPrimary = null, onSecond = null;
            var primaryGot = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var secondGot = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            primary.DataReceived += f => { onPrimary = Ascii(f); primaryGot.TrySetResult(true); };
            second.DataReceived += f => { onSecond = Ascii(f); secondGot.TrySetResult(true); };

            // The LNS echoes each frame back to the session it arrived on, so demux must keep them apart.
            await primary.SendDataAsync(System.Text.Encoding.ASCII.GetBytes("for-primary"));
            await second.SendDataAsync(System.Text.Encoding.ASCII.GetBytes("for-second"));

            await Task.WhenAny(Task.WhenAll(primaryGot.Task, secondGot.Task), Task.Delay(TimeSpan.FromSeconds(5), cts.Token));
            Assert.True(primaryGot.Task.IsCompletedSuccessfully && secondGot.Task.IsCompletedSuccessfully);
            Assert.Equal("for-primary", onPrimary);
            Assert.Equal("for-second", onSecond);

            client.Dispose();
        }

        [Fact]
        public async Task OpenSession_ServerRejectsExtraCallWithCdn_Throws()
        {
            var link = new LoopbackLink();
            var lns = new MultiSessionLns(link.Server, rejectExtra: true);
            var client = new L2tpClient(link.Client, retransmitOptions: new L2tpRetransmitOptions { Interval = TimeSpan.FromSeconds(30) });

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await client.ConnectAsync(cts.Token); // the primary still comes up

            await Assert.ThrowsAnyAsync<IOException>(() => client.OpenSessionAsync(cts.Token));

            client.Dispose();
        }

        static string Ascii(ReadOnlyMemory<byte> b) => System.Text.Encoding.ASCII.GetString(b.ToArray());

        /// <summary>An in-memory bidirectional L2TP link; each side posts datagrams to the other via the thread pool.</summary>
        sealed class LoopbackLink
        {
            readonly Endpoint _client = new();
            readonly Endpoint _server = new();

            public LoopbackLink()
            {
                _client.Peer = _server;
                _server.Peer = _client;
            }

            public IL2tpTransport Client => _client;
            public IL2tpTransport Server => _server;

            sealed class Endpoint : IL2tpTransport
            {
                public Endpoint? Peer;
                public event Action<ReadOnlyMemory<byte>>? DatagramReceived;

                public Task SendAsync(ReadOnlyMemory<byte> datagram)
                {
                    byte[] copy = datagram.ToArray();
                    Endpoint? peer = Peer;
                    _ = Task.Run(() => peer?.DatagramReceived?.Invoke(copy));
                    return Task.CompletedTask;
                }
            }
        }

        /// <summary>
        /// An LNS that admits a tunnel and the first session, then either admits or rejects a second call. Replies
        /// address the client's assigned session id, and data is echoed back to the session it came in on.
        /// </summary>
        sealed class MultiSessionLns
        {
            readonly IL2tpTransport _transport;
            readonly bool _rejectExtra;
            readonly object _sync = new();
            readonly ConcurrentDictionary<ushort, ushort> _serverToClientSession = new(); // our session id → client's
            ushort _ns;
            ushort _nr;
            ushort _clientTunnelId;
            ushort _nextServerSessionId = 0x6000;
            int _sessionsAdmitted;

            public MultiSessionLns(IL2tpTransport transport, bool rejectExtra)
            {
                _transport = transport;
                _rejectExtra = rejectExtra;
                _transport.DatagramReceived += OnDatagram;
            }

            void OnDatagram(ReadOnlyMemory<byte> datagram)
            {
                if (!L2tpCodec.IsControl(datagram.Span))
                {
                    if (L2tpCodec.TryDecodeData(datagram.Span, out _, out ushort sessionId, out byte[] ppp)
                        && _serverToClientSession.TryGetValue(sessionId, out ushort clientSessionId))
                        _ = _transport.SendAsync(L2tpCodec.EncodeData(_clientTunnelId, clientSessionId, ppp));
                    return;
                }

                L2tpControlMessage message = L2tpCodec.DecodeControl(datagram.Span);
                if (message.IsZeroLengthBody) return;
                lock (_sync) _nr = (ushort)(message.Ns + 1);

                switch (message.MessageType)
                {
                    case L2tpMessageType.StartControlConnectionRequest:
                        _clientTunnelId = message.Find(L2tpAvpType.AssignedTunnelId)!.AsUInt16();
                        Reply(L2tpControlMessage.Create(L2tpMessageType.StartControlConnectionReply, _clientTunnelId)
                            .With(L2tpAvp.UInt16(L2tpAvpType.ProtocolVersion, 0x0100))
                            .With(L2tpAvp.UInt32(L2tpAvpType.FramingCapabilities, 3))
                            .With(L2tpAvp.Text(L2tpAvpType.HostName, "lns"))
                            .With(L2tpAvp.UInt16(L2tpAvpType.AssignedTunnelId, 0x5000)));
                        break;

                    case L2tpMessageType.IncomingCallRequest:
                        ushort clientSessionId = message.Find(L2tpAvpType.AssignedSessionId)!.AsUInt16();
                        bool isExtra = Interlocked.Increment(ref _sessionsAdmitted) > 1;
                        if (isExtra && _rejectExtra)
                        {
                            // Reject the extra call: a CDN addressed to the session the client assigned.
                            var cdn = L2tpControlMessage.Create(L2tpMessageType.CallDisconnectNotify, _clientTunnelId)
                                .With(L2tpAvp.UInt16(L2tpAvpType.ResultCode, 2));
                            cdn.SessionId = clientSessionId;
                            Reply(cdn);
                            break;
                        }
                        ushort serverSessionId = _nextServerSessionId++;
                        _serverToClientSession[serverSessionId] = clientSessionId;
                        var icrp = L2tpControlMessage.Create(L2tpMessageType.IncomingCallReply, _clientTunnelId)
                            .With(L2tpAvp.UInt16(L2tpAvpType.AssignedSessionId, serverSessionId));
                        icrp.SessionId = clientSessionId; // address the reply with the client's session id
                        Reply(icrp);
                        break;
                }
            }

            void Reply(L2tpControlMessage message)
            {
                lock (_sync)
                {
                    message.Ns = _ns++;
                    message.Nr = _nr;
                    _ = _transport.SendAsync(L2tpCodec.EncodeControl(message));
                }
            }
        }
    }
}
