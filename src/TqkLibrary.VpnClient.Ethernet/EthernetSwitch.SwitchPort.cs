using TqkLibrary.VpnClient.Abstractions.Channels.Interfaces;

namespace TqkLibrary.VpnClient.Ethernet
{
    public sealed partial class EthernetSwitch
    {
        /// <summary>
        /// A port on the switch fabric, as the switch sees it: the switch learns the source MAC from the frames a port
        /// ingresses (<see cref="EthernetSwitch.OnIngress"/>) and forwards/floods frames to a port by calling
        /// <see cref="Deliver"/>. Two concrete kinds exist — a <see cref="Port"/> (a host the switch owns, exposed to the
        /// host as its <see cref="IEthernetChannel"/>) and an <see cref="UplinkPort"/> (an external VPN uplink channel
        /// the switch forwards onto). Keeping the switch keyed on this base lets the FDB / flood logic treat both
        /// identically.
        /// </summary>
        internal abstract class SwitchPort : IAsyncDisposable
        {
            /// <summary>Switch → port: hand one forwarded/flooded frame to this port (buffer valid only during the call).</summary>
            public abstract void Deliver(ReadOnlyMemory<byte> frame);

            /// <inheritdoc/>
            public abstract ValueTask DisposeAsync();
        }
    }
}
