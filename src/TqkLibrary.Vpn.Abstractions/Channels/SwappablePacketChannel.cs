using TqkLibrary.Vpn.Abstractions.Channels.Enums;
using TqkLibrary.Vpn.Abstractions.Channels.Interfaces;

namespace TqkLibrary.Vpn.Abstractions.Channels
{
    /// <summary>
    /// A stable <see cref="IPacketChannel"/> facade whose inner channel can be hot-swapped — e.g. across a reconnect —
    /// without the bound userspace TCP/IP stack rebinding. Writes and the <see cref="InboundIpPacket"/> event forward
    /// to whatever inner is current; the link metadata is pinned from the first inner so it never changes mid-flight.
    /// While no inner is attached (before the first connect, or briefly during a reconnect) writes are silently
    /// dropped rather than throwing. The forwarder re-raises inbound packets synchronously, preserving the
    /// buffer-lifetime contract of <see cref="IPacketChannel.InboundIpPacket"/> (the buffer is valid only in-handler).
    /// </summary>
    public sealed class SwappablePacketChannel : IPacketChannel
    {
        readonly object _swapLock = new();
        readonly Action<ReadOnlyMemory<byte>> _forward;
        volatile IPacketChannel? _inner;
        bool _pinned;

        /// <summary>Creates an empty facade; call <see cref="SetInner"/> to attach the first (and later) inner channel.</summary>
        public SwappablePacketChannel()
        {
            // A single cached delegate instance so the matching -= in SetInner/DisposeAsync actually detaches.
            _forward = packet => InboundIpPacket?.Invoke(packet);
        }

        /// <inheritdoc/>
        public LinkMedium Medium { get; private set; } = LinkMedium.Ip;

        /// <inheritdoc/>
        public int Mtu { get; private set; } = 1400;

        /// <inheritdoc/>
        public int MaxHeaderLength { get; private set; }

        /// <inheritdoc/>
        public bool RequiresLinkAddressResolution { get; private set; }

        /// <inheritdoc/>
        public event Action<ReadOnlyMemory<byte>>? InboundIpPacket;

        /// <summary>Attaches <paramref name="next"/> as the current inner, detaching the previous one; pins metadata on first use.</summary>
        public void SetInner(IPacketChannel next)
        {
            lock (_swapLock)
            {
                IPacketChannel? old = _inner;
                if (old != null) old.InboundIpPacket -= _forward;

                if (!_pinned)
                {
                    Medium = next.Medium;
                    Mtu = next.Mtu;
                    MaxHeaderLength = next.MaxHeaderLength;
                    RequiresLinkAddressResolution = next.RequiresLinkAddressResolution;
                    _pinned = true;
                }

                _inner = next;
                next.InboundIpPacket += _forward;
            }
        }

        /// <inheritdoc/>
        public ValueTask WriteIpPacketAsync(ReadOnlyMemory<byte> ipPacket, CancellationToken cancellationToken = default)
        {
            IPacketChannel? inner = _inner;
            return inner?.WriteIpPacketAsync(ipPacket, cancellationToken) ?? default;
        }

        /// <inheritdoc/>
        public ValueTask DisposeAsync()
        {
            IPacketChannel? inner;
            lock (_swapLock)
            {
                inner = _inner;
                if (inner != null) inner.InboundIpPacket -= _forward;
                _inner = null;
            }
            return inner?.DisposeAsync() ?? default;
        }
    }
}
