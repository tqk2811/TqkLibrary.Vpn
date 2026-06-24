using System.Net;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Drivers.Nebula.DataChannel;
using TqkLibrary.VpnClient.Drivers.Nebula.Transport;
using TqkLibrary.VpnClient.Nebula.Certificate;
using TqkLibrary.VpnClient.Nebula.Certificate.Models;
using TqkLibrary.VpnClient.Nebula.Handshake;
using TqkLibrary.VpnClient.Nebula.Handshake.Models;
using TqkLibrary.VpnClient.Nebula.Packet;
using TqkLibrary.VpnClient.Nebula.Packet.Enums;
using TqkLibrary.VpnClient.Nebula.Packet.Models;

namespace TqkLibrary.VpnClient.Drivers.Nebula.Tests
{
    /// <summary>
    /// Offline harness for driving the real <see cref="NebulaConnection"/> against an in-process Nebula responder built
    /// from the same protocol blocks (<see cref="NebulaNoiseIxHandshake"/> responder path + <see cref="NebulaTransport"/>).
    /// A lossless ordered in-memory UDP loopback ties the two together. Throwaway test scaffolding — the library is a
    /// client; the responder role exists only here. Mirrors the WireGuard driver's loopback harness.
    /// </summary>
    sealed class LoopbackUdpLink
    {
        readonly Endpoint _client = new();
        readonly Endpoint _server = new();

        public LoopbackUdpLink() { _client.Peer = _server; _server.Peer = _client; }

        public Endpoint Client => _client;
        public Endpoint Server => _server;

        /// <summary>An in-memory connected datagram pipe; each send is delivered to the peer in order on the thread pool.</summary>
        public sealed class Endpoint : IDatagramTransport
        {
            public Endpoint? Peer;
            readonly object _lock = new();
            Task _tail = Task.CompletedTask;
            Action<ReadOnlyMemory<byte>>? _receiver;

            public void SetReceiver(Action<ReadOnlyMemory<byte>> receiver) => _receiver = receiver;

            public ValueTask ConnectAsync(CancellationToken cancellationToken = default) => default;

            public ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken = default)
            {
                byte[] copy = datagram.ToArray();
                Endpoint? peer = Peer;
                if (peer != null)
                    lock (peer._lock)
                        peer._tail = peer._tail.ContinueWith(_ => peer._receiver?.Invoke(copy), TaskScheduler.Default);
                return default;
            }

            public ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
                => throw new NotSupportedException("The loopback link self-pumps via the registered receiver.");

            public ValueTask DisposeAsync() => default;
        }
    }

    /// <summary>An <see cref="INebulaTransportFactory"/> that hands back a fixed in-process pipe (self-pumping loopback).</summary>
    sealed class InProcessNebulaTransportFactory : INebulaTransportFactory
    {
        readonly LoopbackUdpLink.Endpoint _endpoint;
        public InProcessNebulaTransportFactory(LoopbackUdpLink.Endpoint endpoint) => _endpoint = endpoint;

        public Task<NebulaTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken)
            => Task.FromResult(new NebulaTransportHandle(_endpoint, _endpoint.SetReceiver, receivePump: null));
    }

    /// <summary>
    /// A throwaway Nebula responder: it answers a handshake stage-1 with a stage-2 response (running the responder half
    /// of <see cref="NebulaNoiseIxHandshake"/> + embedding its own certificate), derives the AES-256-GCM transport
    /// keys, then opens inbound type-1 message datagrams and echoes each inner packet straight back. The loopback is
    /// lossless and ordered, so no retransmit/reorder logic.
    /// </summary>
    sealed class SimulatedNebulaResponder : IDisposable
    {
        readonly LoopbackUdpLink.Endpoint _transport;
        readonly byte[] _x25519Private;
        readonly byte[] _strippedCert;
        readonly NebulaHeaderCodec _headerCodec = new();
        readonly NebulaHandshakePayloadCodec _payloadCodec = new();
        readonly NebulaCertificateCodec _certCodec = new();
        readonly object _sync = new();

        NebulaTransport? _data;
        uint _responderIndex;

        public int MessagesOpened { get; private set; }

        public SimulatedNebulaResponder(LoopbackUdpLink.Endpoint transport, NebulaCertificate cert, byte[] x25519Private)
        {
            _transport = transport;
            _x25519Private = x25519Private;
            _strippedCert = BuildStrippedCert(cert);
            _transport.SetReceiver(OnInbound);
        }

        byte[] BuildStrippedCert(NebulaCertificate cert)
        {
            var stripped = new NebulaCertificate
            {
                Details = new NebulaCertificateDetails
                {
                    Name = cert.Details.Name,
                    Ips = cert.Details.Ips,
                    Subnets = cert.Details.Subnets,
                    Groups = cert.Details.Groups,
                    NotBefore = cert.Details.NotBefore,
                    NotAfter = cert.Details.NotAfter,
                    PublicKey = Array.Empty<byte>(),
                    IsCa = cert.Details.IsCa,
                    Issuer = cert.Details.Issuer,
                    Curve = cert.Details.Curve,
                },
                Signature = cert.Signature,
            };
            return _certCodec.MarshalCertificate(stripped);
        }

        void OnInbound(ReadOnlyMemory<byte> datagram)
        {
            ReadOnlySpan<byte> span = datagram.Span;
            if (!_headerCodec.TryDecode(span, out NebulaHeader header)) return;
            if (header.Type == NebulaMessageType.Handshake) HandleHandshake(span, header);
            else if (header.Type == NebulaMessageType.Message) HandleMessage(span);
        }

        void HandleHandshake(ReadOnlySpan<byte> span, NebulaHeader header)
        {
            byte[] noiseMsg1 = span.Slice(NebulaHeader.Size).ToArray();
            var handshake = new NebulaNoiseIxHandshake(_x25519Private);
            if (!handshake.ConsumeInitiation(noiseMsg1, out byte[] payload1)) return;

            NebulaHandshakeDetails initDetails = _payloadCodec.Unmarshal(payload1);
            uint initiatorIndex = initDetails.InitiatorIndex;
            uint responderIndex = 0xB0B0CAFEu;

            var respDetails = new NebulaHandshakeDetails
            {
                Cert = _strippedCert,
                InitiatorIndex = initiatorIndex,
                ResponderIndex = responderIndex,
                Time = 1,
            };
            byte[] respPayload = _payloadCodec.Marshal(respDetails);
            byte[] noiseMsg2 = handshake.CreateResponse(respPayload);

            var respHeader = new NebulaHeader
            {
                Version = 1,
                Type = NebulaMessageType.Handshake,
                SubType = (byte)NebulaMessageSubType.HandshakeIxPsk0,
                Reserved = 0,
                RemoteIndex = initiatorIndex, // echo so the initiator can match it
                MessageCounter = 2,
            };
            byte[] packet = _headerCodec.EncodePacket(respHeader, noiseMsg2);

            (byte[] send, byte[] recv) = handshake.Split(); // responder send/recv
            lock (_sync)
            {
                _responderIndex = responderIndex;
                // The responder seals with the index the INITIATOR chose (so the initiator can route), opens with its own.
                _data = new NebulaTransport(send, recv, sendRemoteIndex: initiatorIndex, localIndex: responderIndex);
            }
            _ = _transport.SendAsync(packet);
        }

        void HandleMessage(ReadOnlySpan<byte> span)
        {
            NebulaTransport? data;
            lock (_sync) data = _data;
            if (data is null) return;
            if (!data.TryOpen(span, out byte[] inner)) return;
            MessagesOpened++;
            _ = _transport.SendAsync(data.Seal(inner)); // echo the inner packet back
        }

        /// <summary>Test stimulus: the responder sends an unsolicited inner packet to the client.</summary>
        public void SendToClient(byte[] inner)
        {
            NebulaTransport? data;
            lock (_sync) data = _data;
            if (data != null) _ = _transport.SendAsync(data.Seal(inner));
        }

        public void Dispose() { }
    }
}
