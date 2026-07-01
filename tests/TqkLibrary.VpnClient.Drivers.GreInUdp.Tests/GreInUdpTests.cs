using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Enums;
using TqkLibrary.VpnClient.Abstractions.Drivers.Interfaces;
using TqkLibrary.VpnClient.Abstractions.Drivers.Models;
using TqkLibrary.VpnClient.Abstractions.Transport.Interfaces;
using TqkLibrary.VpnClient.IpEncap.Gre;
using Xunit;

namespace TqkLibrary.VpnClient.Drivers.GreInUdp.Tests
{
    /// <summary>
    /// Offline coverage for the GRE-in-UDP driver runtime (RFC 8086): the reused <see cref="GreTunnelChannel"/> over
    /// a UDP datagram pipe. No admin/server, no <c>Integration</c> trait — the real-socket case uses 127.0.0.1 ephemeral
    /// ports, the others an in-memory loopback link. Covers: real UDP loopback round-trip, GRE-in-UDP byte-for-byte v4/v6
    /// over the loopback link, driver capabilities (no elevation / no raw socket), default port 4754, and the injectable
    /// transport factory driving <see cref="GreInUdpConnection"/> end-to-end.
    /// </summary>
    public class GreInUdpTests
    {
        const string ServerHost = "203.0.113.7"; // TEST-NET-3 literal so the resolver returns it verbatim (no DNS)

        // ---- 1) real UDP loopback: a UdpDatagramTransport client <-> a raw UDP echo peer on 127.0.0.1 ----

        [Fact]
        public async Task Udp_Loopback_GreInUdp_RoundTrips_InnerIpv4PacketBothWays()
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

            // A real UDP peer socket bound to an ephemeral loopback port; it echoes the *inner* IP packet (unwrapping
            // and re-wrapping GRE) back to the client's source once the first datagram reveals it.
            using var peer = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            peer.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            int peerPort = ((IPEndPoint)peer.LocalEndPoint!).Port;

            var peerLoop = Task.Run(() => RunGreEchoPeerAsync(peer, cts.Token));

            // The transport under test: a passive UDP pipe connected to the peer (built by the public production
            // factory); the GRE channel drives its receive loop.
            IDatagramTransport transport = new UdpGreTransportFactory(IPAddress.Loopback)
                .Create(new IPEndPoint(IPAddress.Loopback, peerPort));
            await transport.ConnectAsync(cts.Token);
            await using var channel = new GreTunnelChannel(transport);

            var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            channel.InboundIpPacket += p => received.TrySetResult(p.ToArray());
            channel.Start();

            // client → peer (GRE-in-UDP) → peer echoes the inner packet back GRE-wrapped → surfaces on the channel.
            byte[] inner = BuildIpv4Packet(0x11);
            await channel.WriteIpPacketAsync(inner, cts.Token);

            byte[] echoed = await WaitAsync(received.Task, cts.Token);
            Assert.Equal(inner, echoed);

            cts.Cancel();
            try { await peerLoop; } catch { }
        }

        // A raw UDP peer that GRE-decodes each inbound datagram and echoes the inner IP packet back GRE-wrapped to the
        // sender's source endpoint. Proves the client transport really sends/receives GRE-in-UDP over a real socket.
        static async Task RunGreEchoPeerAsync(Socket peer, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[2048];
            var any = new IPEndPoint(IPAddress.Loopback, 0);
            using (cancellationToken.Register(() => { try { peer.Dispose(); } catch { } }))
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    SocketReceiveFromResult r = await peer.ReceiveFromAsync(new ArraySegment<byte>(buffer), SocketFlags.None, any).ConfigureAwait(false);
                    if (r.ReceivedBytes <= 0) continue;
                    if (!GreCodec.TryDecode(buffer.AsSpan(0, r.ReceivedBytes), out GrePacket? p) || p is null) continue;
                    byte[] reply = GreCodec.Encode(new GrePacket { ProtocolType = p.ProtocolType, Payload = p.Payload });
                    await peer.SendToAsync(new ArraySegment<byte>(reply), SocketFlags.None, r.RemoteEndPoint).ConfigureAwait(false);
                }
            }
        }

        // ---- 2) GRE-in-UDP round-trip v4 + v6 byte-for-byte over the in-memory loopback link ----

        [Fact]
        public async Task LoopbackLink_GreInUdp_RoundTrips_InnerIpv4ByteForByte()
        {
            var link = new LoopbackDatagramLink();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            await using var a = new GreTunnelChannel(link.A, new GreTunnelOptions { Key = 0x12345678, EmitSequenceNumber = true });
            await using var b = new GreTunnelChannel(link.B);

            var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            b.InboundIpPacket += p => received.TrySetResult(p.ToArray());
            a.Start();
            b.Start();

            byte[] inner = BuildIpv4Packet(0xAB);
            await a.WriteIpPacketAsync(inner, cts.Token);
            Assert.Equal(inner, await WaitAsync(received.Task, cts.Token));
        }

        [Fact]
        public async Task LoopbackLink_GreInUdp_RoundTrips_InnerIpv6ByteForByte()
        {
            var link = new LoopbackDatagramLink();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            await using var a = new GreTunnelChannel(link.A, new GreTunnelOptions { EmitChecksum = true });
            await using var b = new GreTunnelChannel(link.B);

            var received = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            b.InboundIpPacket += p => received.TrySetResult(p.ToArray());
            a.Start();
            b.Start();

            byte[] inner = BuildIpv6Packet(0xCD);
            await a.WriteIpPacketAsync(inner, cts.Token);
            Assert.Equal(inner, await WaitAsync(received.Task, cts.Token));
        }

        // ---- 3) driver capabilities: no elevation, no raw socket, name "gre-udp", UDP transport ----

        [Fact]
        public void Driver_ExposesGreInUdpCapabilities()
        {
            var driver = new GreInUdpDriver();

            Assert.Equal("gre-udp", driver.Name);
            Assert.False(driver.Capabilities.UsesPpp);
            Assert.False(driver.Capabilities.RequiresElevation);
            Assert.False(driver.Capabilities.RequiresRawIpSocket);
            Assert.Equal(VpnLinkLayer.L3Ip, driver.Capabilities.LinkLayer);
            Assert.True((driver.Capabilities.TransportKinds & VpnTransportKind.Udp) != 0);
            Assert.Equal(VpnSecurityKind.None, driver.Capabilities.SecurityKinds);
            Assert.Equal(VpnAuthMethod.None, driver.Capabilities.AuthMethods);
            Assert.Equal(AddressAssignment.OutOfBand, driver.Capabilities.AddressAssignment);
        }

        // ---- 4) default port 4754 (IANA GRE-in-UDP) ----

        [Fact]
        public void Options_DefaultPort_Is4754()
        {
            Assert.Equal(4754, new GreInUdpOptions().Port);
        }

        // ---- 5) injectable factory: GreInUdpConnection establishes + carries a packet over a fake transport ----

        [Fact]
        public async Task Connection_WithInjectedFactory_EstablishesAndCarriesPacket()
        {
            var link = new LoopbackDatagramLink();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            var driver = new GreInUdpDriver(new GreInUdpOptions { Mtu = 1400 },
                transportFactory: new FakeGreUdpTransportFactory(link.A));
            await using IVpnConnection connection = await driver.ConnectAsync(
                new VpnEndpoint(ServerHost, 0), new VpnCredentials(), cts.Token);
            IPacketChannel channel = connection.Sessions[0].PacketChannel;

            // client → peer: the inner IPv4 packet must reach the peer GRE-wrapped and decode back to the same bytes.
            byte[] innerOut = BuildIpv4Packet(0x33);
            await channel.WriteIpPacketAsync(innerOut, cts.Token);

            byte[] datagram = await ReceiveDatagramAsync(link.B, cts.Token);
            Assert.True(GreCodec.TryDecode(datagram, out GrePacket? wrapped) && wrapped is not null);
            Assert.Equal(GreCodec.ProtocolTypeIpv4, wrapped!.ProtocolType);
            Assert.Equal(innerOut, wrapped.Payload.ToArray());

            // peer → client: a GRE frame carrying an inner IPv4 packet must surface on InboundIpPacket verbatim.
            var inbound = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
            channel.InboundIpPacket += p => inbound.TrySetResult(p.ToArray());

            byte[] innerIn = BuildIpv4Packet(0x44);
            byte[] greIn = GreCodec.Encode(new GrePacket { ProtocolType = GreCodec.ProtocolTypeIpv4, Payload = innerIn });
            await link.B.SendAsync(greIn, cts.Token);

            Assert.Equal(innerIn, await WaitAsync(inbound.Task, cts.Token));
        }

        [Fact]
        public void Connection_NullTransportFactory_Throws()
        {
            Assert.Throws<ArgumentNullException>(() => new GreInUdpConnection(ServerHost, null!));
        }

        // ---- helpers ----

        // A minimal but version-correct IPv4 packet (first nibble 4) so the GRE channel picks ProtocolTypeIpv4.
        static byte[] BuildIpv4Packet(byte marker)
        {
            byte[] p = new byte[20];
            p[0] = 0x45; // version 4, IHL 5
            p[9] = 0xFE; // some protocol
            p[19] = marker;
            return p;
        }

        // A minimal IPv6 packet (first nibble 6) so the GRE channel picks ProtocolTypeIpv6.
        static byte[] BuildIpv6Packet(byte marker)
        {
            byte[] p = new byte[40];
            p[0] = 0x60; // version 6
            p[39] = marker;
            return p;
        }

        static async Task<byte[]> ReceiveDatagramAsync(LoopbackDatagramLink.End end, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[2048];
            int n = await end.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
            return buffer.AsMemory(0, n).ToArray();
        }

        static async Task<T> WaitAsync<T>(Task<T> task, CancellationToken cancellationToken)
        {
            var cancelled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            using (cancellationToken.Register(() => cancelled.TrySetResult(true)))
            {
                if (await Task.WhenAny(task, cancelled.Task).ConfigureAwait(false) != task)
                    cancellationToken.ThrowIfCancellationRequested();
                return await task.ConfigureAwait(false);
            }
        }

        /// <summary>A fake <see cref="IGreUdpTransportFactory"/> handing out one preconfigured loopback datagram end as the UDP pipe.</summary>
        sealed class FakeGreUdpTransportFactory : IGreUdpTransportFactory
        {
            readonly IDatagramTransport _transport;
            public FakeGreUdpTransportFactory(IDatagramTransport transport) => _transport = transport;
            public IDatagramTransport Create(IPEndPoint remote) => _transport;
        }
    }
}
