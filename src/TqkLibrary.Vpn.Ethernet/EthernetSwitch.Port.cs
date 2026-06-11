using TqkLibrary.Vpn.Abstractions.Channels.Enums;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;

namespace TqkLibrary.Vpn.Ethernet
{
    public sealed partial class EthernetSwitch
    {
        /// <summary>
        /// One switch port, seen by the attached host as its <see cref="IEthernetChannel"/>: the host writes frames
        /// in via <see cref="WriteFrameAsync"/> (switch ingress) and receives forwarded frames via
        /// <see cref="InboundFrame"/>. The switch owns it; the host only sees the interface.
        /// </summary>
        sealed class Port : IEthernetChannel
        {
            readonly EthernetSwitch _switch;
            readonly byte[] _linkAddress;
            readonly int _mtu;
            bool _disposed;

            public Port(EthernetSwitch ethernetSwitch, MacAddress hostMac, int mtu)
            {
                _switch = ethernetSwitch;
                _linkAddress = hostMac.ToArray();
                _mtu = mtu;
            }

            public LinkMedium Medium => LinkMedium.Ethernet;
            public int Mtu => _mtu;
            public int MaxHeaderLength => EthernetFrame.HeaderLength;
            public bool RequiresLinkAddressResolution => true;
            public ReadOnlyMemory<byte> LinkAddress => _linkAddress;
            public event Action<ReadOnlyMemory<byte>>? InboundFrame;

            /// <summary>Host → switch: hand the frame to the switch for learning + forwarding.</summary>
            public ValueTask WriteFrameAsync(ReadOnlyMemory<byte> ethernetFrame, CancellationToken cancellationToken = default)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!_disposed)
                    _switch.OnIngress(this, ethernetFrame);
                return default;
            }

            /// <summary>Switch → host: raise the inbound event (buffer valid only during the handler).</summary>
            public void Deliver(ReadOnlyMemory<byte> frame) => InboundFrame?.Invoke(frame);

            public ValueTask DisposeAsync()
            {
                if (!_disposed)
                {
                    _disposed = true;
                    InboundFrame = null;
                    _switch.RemovePort(this);
                }
                return default;
            }
        }
    }
}
