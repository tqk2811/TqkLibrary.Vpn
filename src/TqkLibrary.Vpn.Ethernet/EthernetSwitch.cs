using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;

namespace TqkLibrary.Vpn.Ethernet
{
    /// <summary>
    /// An in-memory learning Ethernet switch (the L2 fabric of an <c>EthernetAdapter</c>). Each host attaches via
    /// <see cref="ConnectHost"/> and gets its own <see cref="IEthernetChannel"/> port. The switch learns
    /// source-MAC→port (a forwarding database) from inbound frames and forwards by destination MAC: a known unicast
    /// goes to exactly one port; broadcast, multicast, and unknown-unicast flood every other port (RFC-less classic
    /// transparent bridging, IEEE 802.1D §7 without STP).
    /// </summary>
    /// <remarks>
    /// Deliberately omitted: FDB aging/timeout (entries live until the port disconnects or the MAC moves), Spanning
    /// Tree, VLAN tagging, and IGMP/MLD snooping (every multicast floods). Frames are forwarded unchanged.
    /// </remarks>
    public sealed partial class EthernetSwitch : IAsyncDisposable
    {
        readonly object _sync = new object();
        readonly List<Port> _ports = new List<Port>();
        readonly Dictionary<MacAddress, Port> _fdb = new Dictionary<MacAddress, Port>();
        readonly int _mtu;
        bool _disposed;

        /// <summary>Creates a switch whose ports advertise <paramref name="mtu"/> payload bytes (default 1500).</summary>
        public EthernetSwitch(int mtu = 1500) => _mtu = mtu;

        /// <summary>Number of ports currently attached.</summary>
        public int PortCount
        {
            get { lock (_sync) return _ports.Count; }
        }

        /// <summary>
        /// Attaches a host and returns its L2 port. <paramref name="hostMac"/> is the port's own
        /// <see cref="IEthernetChannel.LinkAddress"/>; the FDB still learns the MAC from the frames the host sends
        /// (a host that never transmits stays unknown, so frames addressed to it flood).
        /// </summary>
        public IEthernetChannel ConnectHost(MacAddress hostMac)
        {
            var port = new Port(this, hostMac, _mtu);
            lock (_sync)
            {
                if (_disposed) throw new ObjectDisposedException(nameof(EthernetSwitch));
                _ports.Add(port);
            }
            return port;
        }

        /// <summary>Ingress from one port: learn the source MAC, then forward by destination MAC.</summary>
        void OnIngress(Port source, ReadOnlyMemory<byte> frame)
        {
            if (frame.Length < EthernetFrame.HeaderLength) return;
            MacAddress src = EthernetFrame.Source(frame.Span);
            MacAddress dst = EthernetFrame.Destination(frame.Span);

            Port? unicastTarget = null;
            List<Port>? floodTargets = null;
            lock (_sync)
            {
                if (_disposed) return;
                _fdb[src] = source;   // learn / MAC-move (overwrites the prior port)

                if (!dst.IsMulticast && _fdb.TryGetValue(dst, out Port? known))
                {
                    if (known == source) return;   // destination is the sender's own port → drop, never reflect
                    unicastTarget = known;
                }
                else
                {
                    // Broadcast, multicast, or unknown-unicast → flood every port except the ingress one.
                    floodTargets = new List<Port>(_ports.Count);
                    foreach (Port port in _ports)
                        if (port != source) floodTargets.Add(port);
                }
            }

            // Deliver outside the lock: a host's InboundFrame handler may write back synchronously (re-entering OnIngress).
            if (unicastTarget != null)
                unicastTarget.Deliver(frame);
            else if (floodTargets != null)
                foreach (Port port in floodTargets)
                    port.Deliver(frame);
        }

        /// <summary>Detaches a port and purges every FDB entry pointing at it.</summary>
        void RemovePort(Port port)
        {
            lock (_sync)
            {
                _ports.Remove(port);
                List<MacAddress>? stale = null;
                foreach (KeyValuePair<MacAddress, Port> entry in _fdb)
                    if (entry.Value == port)
                        (stale ??= new List<MacAddress>()).Add(entry.Key);
                if (stale != null)
                    foreach (MacAddress mac in stale)
                        _fdb.Remove(mac);
            }
        }

        public async ValueTask DisposeAsync()
        {
            Port[] ports;
            lock (_sync)
            {
                if (_disposed) return;
                _disposed = true;
                ports = _ports.ToArray();
                _ports.Clear();
                _fdb.Clear();
            }
            foreach (Port port in ports)
                await port.DisposeAsync().ConfigureAwait(false);
        }
    }
}
