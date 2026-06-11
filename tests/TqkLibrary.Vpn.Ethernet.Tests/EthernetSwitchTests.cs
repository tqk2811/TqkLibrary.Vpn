using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;
using TqkLibrary.Vpn.Ethernet;
using Xunit;

namespace TqkLibrary.Vpn.Ethernet.Tests
{
    public class EthernetSwitchTests
    {
        static readonly MacAddress MacA = MacAddress.Parse("02:00:00:00:00:0a");
        static readonly MacAddress MacB = MacAddress.Parse("02:00:00:00:00:0b");
        static readonly MacAddress MacC = MacAddress.Parse("02:00:00:00:00:0c");
        static readonly MacAddress MacD = MacAddress.Parse("02:00:00:00:00:0d");

        /// <summary>Attaches a host and records every frame the switch delivers to it.</summary>
        static (IEthernetChannel channel, List<byte[]> received) Connect(EthernetSwitch ethernetSwitch, MacAddress mac)
        {
            IEthernetChannel channel = ethernetSwitch.ConnectHost(mac);
            var received = new List<byte[]>();
            channel.InboundFrame += frame => received.Add(frame.ToArray());
            return (channel, received);
        }

        static byte[] Frame(MacAddress destination, MacAddress source) =>
            EthernetFrame.Build(destination, source, EthernetFrame.EtherTypeIpv4, new byte[] { 1, 2, 3, 4 });

        [Fact]
        public async Task UnknownUnicast_FloodsEveryPortExceptIngress()
        {
            var sw = new EthernetSwitch();
            var (a, rxA) = Connect(sw, MacA);
            var (_, rxB) = Connect(sw, MacB);
            var (_, rxC) = Connect(sw, MacC);

            // B has never transmitted → its MAC is unknown → the frame floods.
            await a.WriteFrameAsync(Frame(MacB, MacA));

            Assert.Empty(rxA);          // never reflected to the sender's port
            Assert.Single(rxB);
            Assert.Single(rxC);
        }

        [Fact]
        public async Task LearnedUnicast_GoesOnlyToDestinationPort()
        {
            var sw = new EthernetSwitch();
            var (a, rxA) = Connect(sw, MacA);
            var (b, rxB) = Connect(sw, MacB);
            var (_, rxC) = Connect(sw, MacC);

            await b.WriteFrameAsync(Frame(MacA, MacB));   // B transmits → switch learns MacB → B's port
            rxA.Clear(); rxB.Clear(); rxC.Clear();

            await a.WriteFrameAsync(Frame(MacB, MacA));   // now A→B is a known unicast

            Assert.Single(rxB);
            Assert.Empty(rxC);          // not flooded to the third port
            Assert.Empty(rxA);
        }

        [Fact]
        public async Task Broadcast_FloodsEveryPortExceptIngress()
        {
            var sw = new EthernetSwitch();
            var (a, rxA) = Connect(sw, MacA);
            var (_, rxB) = Connect(sw, MacB);
            var (_, rxC) = Connect(sw, MacC);

            await a.WriteFrameAsync(Frame(MacAddress.Broadcast, MacA));

            Assert.Empty(rxA);
            Assert.Single(rxB);
            Assert.Single(rxC);
        }

        [Fact]
        public async Task Ipv6Multicast_FloodsEveryPortExceptIngress()
        {
            var sw = new EthernetSwitch();
            var (a, rxA) = Connect(sw, MacA);
            var (_, rxB) = Connect(sw, MacB);
            var (_, rxC) = Connect(sw, MacC);

            await a.WriteFrameAsync(Frame(MacAddress.Parse("33:33:00:00:00:01"), MacA));

            Assert.Empty(rxA);
            Assert.Single(rxB);
            Assert.Single(rxC);
        }

        [Fact]
        public async Task UnicastToOwnPort_IsDropped_NeverReflected()
        {
            var sw = new EthernetSwitch();
            var (a, rxA) = Connect(sw, MacA);
            var (_, rxB) = Connect(sw, MacB);

            // A transmits with destination = its own MAC; after learning, the destination resolves to A's own port → drop.
            await a.WriteFrameAsync(Frame(MacA, MacA));

            Assert.Empty(rxA);
            Assert.Empty(rxB);   // not a flood case — the destination is known (the ingress port itself)
        }

        [Fact]
        public async Task MacMove_RelearnsDestinationOnNewPort()
        {
            var sw = new EthernetSwitch();
            var (a, rxA) = Connect(sw, MacA);
            var (b, rxB) = Connect(sw, MacB);
            var (d, rxD) = Connect(sw, MacD);

            // Warm-up: let the switch learn both MacA and MacB (the first frame to each floods — ignore it).
            await a.WriteFrameAsync(Frame(MacB, MacA));   // learn MacA → A's port
            await b.WriteFrameAsync(Frame(MacA, MacB));   // learn MacB → B's port
            rxA.Clear(); rxB.Clear(); rxD.Clear();

            await a.WriteFrameAsync(Frame(MacB, MacA));    // A→B is a known unicast → only B
            Assert.Single(rxB);
            Assert.Empty(rxD);

            // MacB now appears on D's port (host moved) → FDB must relearn it onto D's port.
            await d.WriteFrameAsync(Frame(MacA, MacB));
            rxA.Clear(); rxB.Clear(); rxD.Clear();

            await a.WriteFrameAsync(Frame(MacB, MacA));

            Assert.Single(rxD);   // follows the new port
            Assert.Empty(rxB);
        }

        [Fact]
        public async Task Disconnect_PurgesFdbAndFloodSet_AndDropsPortCount()
        {
            var sw = new EthernetSwitch();
            var (a, _) = Connect(sw, MacA);
            var (b, rxB) = Connect(sw, MacB);
            var (_, rxC) = Connect(sw, MacC);

            await b.WriteFrameAsync(Frame(MacA, MacB));   // learn MacB (this first frame floods to A,C — ignore)
            Assert.Equal(3, sw.PortCount);

            await b.DisposeAsync();
            Assert.Equal(2, sw.PortCount);
            rxB.Clear(); rxC.Clear();

            // MacB is gone from the FDB → A→B is unknown again → floods to the remaining port (C), not the dead one.
            await a.WriteFrameAsync(Frame(MacB, MacA));

            Assert.Single(rxC);
            Assert.Empty(rxB);   // detached port receives nothing
        }

        [Fact]
        public async Task DisposeAsync_DetachesAllPorts()
        {
            var sw = new EthernetSwitch();
            var (_, rxA) = Connect(sw, MacA);
            var (b, _) = Connect(sw, MacB);

            await sw.DisposeAsync();

            Assert.Equal(0, sw.PortCount);
            // Writing through a port after the switch is gone is a silent no-op (host detached).
            await b.WriteFrameAsync(Frame(MacA, MacB));
            Assert.Empty(rxA);
        }
    }
}
