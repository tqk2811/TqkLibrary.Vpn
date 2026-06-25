using System;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.Crypto.Noise;
using TqkLibrary.VpnClient.Drivers.Tailscale.Config;
using TqkLibrary.VpnClient.Drivers.WireGuard.Transport;
using TqkLibrary.VpnClient.Tailscale.Control.Messages;
using TqkLibrary.VpnClient.Tailscale.Keys;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.Tailscale.Tests
{
    /// <summary>
    /// End-to-end offline proof of the <b>full Tailscale stack between two .NET nodes</b>: each node logs into a fake
    /// ts2021 control plane (a canned netmap listing the other node as its single peer, with that peer's WireGuard
    /// public key + a direct endpoint), the netmap is mapped to a multi-peer <see cref="WireGuard.Config.WireGuardConfig"/>,
    /// and the real <see cref="TailscaleConnection"/> brings a real WireGuard data plane up — using the <b>responder
    /// role</b> so the two nodes hand-shake each other without a server. Then an IP packet round-trips both directions
    /// over the type-4 transport. This is the offline mirror of the live Headscale lab (two .NET clients, ICMP both
    /// ways): the control plane is faked, but the netmap mapping, the tie-break, the Noise_IKpsk2 handshake (one side
    /// initiates, the other responds) and the data plane all run for real.
    /// </summary>
    public class TailscaleTwoNodeTunnelTests
    {
        [Fact]
        public async Task TwoNodes_LoginNetmap_BringUpWireGuard_RoundTripBothDirections()
        {
            var dh = new Curve25519DhGroup();

            // Two WireGuard (= Tailscale node) identities. The node private key is the WireGuard private key.
            byte[] aPriv = dh.GeneratePrivateKey();
            byte[] aPub = dh.DerivePublicValue(aPriv);
            byte[] bPriv = dh.GeneratePrivateKey();
            byte[] bPub = dh.DerivePublicValue(bPriv);

            // Fake endpoints the netmap advertises (the in-process WG factory ignores the address and pumps a loopback).
            var aEndpoint = new IPEndPoint(IPAddress.Parse("10.9.0.1"), 41641);
            var bEndpoint = new IPEndPoint(IPAddress.Parse("10.9.0.2"), 41641);

            // Node A's netmap: self 100.64.0.1, single peer = node B (B's nodekey + a direct endpoint).
            MapResponse mapForA = NetmapBetween(selfPub: aPub, selfAddr: "100.64.0.1/32",
                peerPub: bPub, peerAddr: "100.64.0.2/32", peerEndpoint: bEndpoint, selfId: 1, peerId: 2);
            // Node B's netmap: the mirror.
            MapResponse mapForB = NetmapBetween(selfPub: bPub, selfAddr: "100.64.0.2/32",
                peerPub: aPub, peerAddr: "100.64.0.1/32", peerEndpoint: aEndpoint, selfId: 2, peerId: 1);

            // One bidirectional loopback between the two nodes' WireGuard sockets.
            var link = new WgLoopback();

            var configA = TailscaleConfig.Generate(new Uri("http://headscale:8080"), "preauth-A");
            configA = WithNodeKey(configA, aPriv);
            var configB = TailscaleConfig.Generate(new Uri("http://headscale:8080"), "preauth-B");
            configB = WithNodeKey(configB, bPriv);

            var connA = new TailscaleConnection(configA,
                wireGuardTransportFactory: new FixedWgTransportFactory(link.A),
                controlClientFactory: _ => new FakeTailscaleControlClient(mapForA));
            var connB = new TailscaleConnection(configB,
                wireGuardTransportFactory: new FixedWgTransportFactory(link.B),
                controlClientFactory: _ => new FakeTailscaleControlClient(mapForB));

            var inboundA = Channel.CreateUnbounded<byte[]>();
            var inboundB = Channel.CreateUnbounded<byte[]>();
            connA.PacketChannel.InboundIpPacket += m => inboundA.Writer.TryWrite(m.ToArray());
            connB.PacketChannel.InboundIpPacket += m => inboundB.Writer.TryWrite(m.ToArray());

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await Task.WhenAll(connA.ConnectAsync(cts.Token), connB.ConnectAsync(cts.Token));

            // A → B and B → A over the WireGuard tunnel both nodes brought up via the responder role.
            byte[] aToB = Encoding.ASCII.GetBytes("tailscale node A to node B");
            await connA.PacketChannel.WriteIpPacketAsync(aToB, cts.Token);
            Assert.Equal(aToB, await inboundB.Reader.ReadAsync(cts.Token));

            byte[] bToA = Encoding.ASCII.GetBytes("tailscale node B back to node A");
            await connB.PacketChannel.WriteIpPacketAsync(bToA, cts.Token);
            Assert.Equal(bToA, await inboundA.Reader.ReadAsync(cts.Token));

            await connA.DisposeAsync();
            await connB.DisposeAsync();
        }

        // ---- helpers ----

        static MapResponse NetmapBetween(byte[] selfPub, string selfAddr, byte[] peerPub, string peerAddr,
            IPEndPoint peerEndpoint, long selfId, long peerId) => new MapResponse
        {
            Node = new TailscaleNode { ID = selfId, Key = TailscaleKey.EncodeNodePublic(selfPub), Addresses = new[] { selfAddr } },
            Peers = new[]
            {
                new TailscaleNode
                {
                    ID = peerId,
                    Key = TailscaleKey.EncodeNodePublic(peerPub),
                    AllowedIPs = new[] { peerAddr },
                    Endpoints = new[] { peerEndpoint.ToString() },
                },
            },
        };

        // Rewrite a generated config so its node (= WireGuard) private key is the one we control.
        static TailscaleConfig WithNodeKey(TailscaleConfig baseConfig, byte[] nodePrivateKey) => new TailscaleConfig
        {
            ServerUrl = baseConfig.ServerUrl,
            PreauthKey = baseConfig.PreauthKey,
            Hostname = baseConfig.Hostname,
            MachinePrivateKey = baseConfig.MachinePrivateKey,
            NodePrivateKey = nodePrivateKey,
            Mtu = baseConfig.Mtu,
        };

        /// <summary>An in-process WireGuard UDP factory that always hands back one fixed self-pumping loopback endpoint.</summary>
        sealed class FixedWgTransportFactory : IWireGuardTransportFactory
        {
            readonly WgLoopback.Endpoint _endpoint;
            public FixedWgTransportFactory(WgLoopback.Endpoint endpoint) => _endpoint = endpoint;
            public Task<WireGuardTransportHandle> ConnectAsync(IPEndPoint remote, CancellationToken cancellationToken)
                => Task.FromResult(new WireGuardTransportHandle(_endpoint, _endpoint.SetReceiver, receivePump: null));
        }

        /// <summary>A lossless ordered in-memory datagram loopback wiring node A's socket to node B's and back.</summary>
        sealed class WgLoopback
        {
            public WgLoopback() { A.Peer = B; B.Peer = A; }
            public Endpoint A { get; } = new();
            public Endpoint B { get; } = new();

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
                    => throw new NotSupportedException("The loopback self-pumps via the registered receiver.");

                public ValueTask DisposeAsync() => default;
            }
        }
    }
}
