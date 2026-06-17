using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;

namespace TqkLibrary.VpnClient.Ethernet
{
    public sealed partial class EthernetSwitch
    {
        /// <summary>
        /// A switch port backed by an external VPN uplink channel (the tunnel toward the server), as opposed to a
        /// <see cref="Port"/> the switch owns. Egress (switch → tunnel): <see cref="Deliver"/> writes the frame out the
        /// uplink's <see cref="IEthernetChannel.WriteFrameAsync"/> — fire-and-forget, mirroring the synchronous
        /// switch/ARP write pattern (an in-memory or socket channel completes the write itself). Ingress (tunnel →
        /// switch): inbound frames raised on <see cref="IEthernetChannel.InboundFrame"/> are fed into
        /// <see cref="EthernetSwitch.OnIngress"/>, so the server's frames are learned and forwarded to the right station.
        /// The switch never disposes the caller-owned uplink; <see cref="DisposeAsync"/> only unsubscribes and detaches.
        /// </summary>
        internal sealed class UplinkPort : SwitchPort
        {
            readonly EthernetSwitch _switch;
            readonly IEthernetChannel _uplink;
            volatile bool _disposed;

            public UplinkPort(EthernetSwitch ethernetSwitch, IEthernetChannel uplink)
            {
                _switch = ethernetSwitch;
                _uplink = uplink;
            }

            /// <summary>Begins ingressing inbound uplink frames — called once the port is registered in the fabric.</summary>
            public void Subscribe() => _uplink.InboundFrame += OnUplinkFrame;

            /// <summary>Tunnel → switch: an inbound uplink frame is ingressed (learned + forwarded) like any port.</summary>
            void OnUplinkFrame(ReadOnlyMemory<byte> frame)
            {
                if (!_disposed)
                    _switch.OnIngress(this, frame);
            }

            /// <summary>Switch → tunnel: write the forwarded/flooded frame out the uplink (fire-and-forget).</summary>
            public override void Deliver(ReadOnlyMemory<byte> frame)
            {
                if (_disposed) return;
                // Copy: the buffer is only valid during this synchronous deliver call, but the uplink's write may be
                // asynchronous (a socket transport), so it must own its own bytes.
                _ = _uplink.WriteFrameAsync(frame.ToArray());
            }

            public override ValueTask DisposeAsync()
            {
                if (!_disposed)
                {
                    _disposed = true;
                    _uplink.InboundFrame -= OnUplinkFrame;
                    _switch.RemovePort(this);
                }
                return default;
            }
        }
    }
}
