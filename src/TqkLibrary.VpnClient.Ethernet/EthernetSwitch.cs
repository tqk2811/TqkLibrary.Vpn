using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;

namespace TqkLibrary.VpnClient.Ethernet
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
        readonly List<SwitchPort> _ports = new List<SwitchPort>();
        readonly Dictionary<MacAddress, SwitchPort> _fdb = new Dictionary<MacAddress, SwitchPort>();
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

        /// <summary>
        /// Attaches an external VPN uplink channel as a switch port (an <i>uplink port</i>), bridging the whole broadcast
        /// domain onto the tunnel: frames the switch forwards/floods to this port are written out
        /// <paramref name="uplink"/> (toward the tunnel peer), and frames arriving on <paramref name="uplink.InboundFrame"/>
        /// are ingressed into the switch — learned and forwarded to the right station port. This is what lets an L2 driver
        /// (SoftEther, OpenVPN-tap) expose a multi-host LAN where the server itself answers ARP and serves DHCP per
        /// station, instead of hand-bridging a single host down to L3.
        /// <para>
        /// The returned handle's <see cref="UplinkPortHandle.DisposeAsync"/> detaches the port (it never disposes the
        /// caller-owned <paramref name="uplink"/>). The switch does not own the uplink channel's lifetime.
        /// </para>
        /// </summary>
        public UplinkPortHandle ConnectUplink(IEthernetChannel uplink)
        {
            if (uplink is null) throw new ArgumentNullException(nameof(uplink));
            var port = new UplinkPort(this, uplink);
            lock (_sync)
            {
                if (_disposed) throw new ObjectDisposedException(nameof(EthernetSwitch));
                _ports.Add(port);
            }
            port.Subscribe();   // start ingressing inbound frames only once the port is in the fabric
            return new UplinkPortHandle(port);
        }

        /// <summary>Ingress from one port: learn the source MAC, then forward by destination MAC.</summary>
        void OnIngress(SwitchPort source, ReadOnlyMemory<byte> frame)
        {
            if (frame.Length < EthernetFrame.HeaderLength) return;
            MacAddress src = EthernetFrame.Source(frame.Span);
            MacAddress dst = EthernetFrame.Destination(frame.Span);

            SwitchPort? unicastTarget = null;
            List<SwitchPort>? floodTargets = null;
            lock (_sync)
            {
                if (_disposed) return;
                _fdb[src] = source;   // learn / MAC-move (overwrites the prior port)

                if (!dst.IsMulticast && _fdb.TryGetValue(dst, out SwitchPort? known))
                {
                    if (known == source) return;   // destination is the sender's own port → drop, never reflect
                    unicastTarget = known;
                }
                else
                {
                    // Broadcast, multicast, or unknown-unicast → flood every port except the ingress one.
                    floodTargets = new List<SwitchPort>(_ports.Count);
                    foreach (SwitchPort port in _ports)
                        if (port != source) floodTargets.Add(port);
                }
            }

            // Deliver outside the lock: a host's InboundFrame handler may write back synchronously (re-entering OnIngress).
            if (unicastTarget != null)
                unicastTarget.Deliver(frame);
            else if (floodTargets != null)
                foreach (SwitchPort port in floodTargets)
                    port.Deliver(frame);
        }

        /// <summary>Detaches a port and purges every FDB entry pointing at it.</summary>
        void RemovePort(SwitchPort port)
        {
            lock (_sync)
            {
                _ports.Remove(port);
                List<MacAddress>? stale = null;
                foreach (KeyValuePair<MacAddress, SwitchPort> entry in _fdb)
                    if (entry.Value == port)
                        (stale ??= new List<MacAddress>()).Add(entry.Key);
                if (stale != null)
                    foreach (MacAddress mac in stale)
                        _fdb.Remove(mac);
            }
        }

        public async ValueTask DisposeAsync()
        {
            SwitchPort[] ports;
            lock (_sync)
            {
                if (_disposed) return;
                _disposed = true;
                ports = _ports.ToArray();
                _ports.Clear();
                _fdb.Clear();
            }
            foreach (SwitchPort port in ports)
                await port.DisposeAsync().ConfigureAwait(false);
        }
    }
}
